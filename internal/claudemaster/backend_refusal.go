package claudemaster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// The session must see errors exactly as Anthropic sends them, so the client reacts as it would
// to Anthropic: an upstream error is relayed byte for byte (status, body, the headers Claude Code
// acts on), even when the scheduler retried after it and the pool then refused. Only a refusal
// with no upstream error behind it is synthesized, in Anthropic's error shape, with the type and
// status the client would get from Anthropic for that situation.

type backendRefusalKind int

const (
	backendRefusalUnavailable backendRefusalKind = iota // 529 overloaded_error: retry later (a cooldown, an active handoff)
	backendRefusalQuota                                 // 429 rate_limit_error: every usable subscription is out of weekly quota
	backendRefusalInvalid                               // 400 invalid_request_error: opaque state the pool will not move
	backendRefusalNotFound                              // 404 not_found_error: the bound subscription does not serve the model
	backendRefusalInternal                              // 500 api_error: the pool's own fault
)

// backendRefusalError is a refusal the selector wrote itself: the reason is what the session
// reads, the kind decides the Anthropic error type and status, and the wrapped core error (when
// there is one) is what the scheduler keeps deciding by, so explaining a refusal changes nothing
// about routing.
type backendRefusalError struct {
	kind    backendRefusalKind
	reason  string
	resetAt time.Time // quota: when the earliest subscription resets, for retry-after
	authID  string    // bound-subscription refusals: which subscription, for the remembered upstream error
	model   string
	cause   error
}

func (e *backendRefusalError) Error() string { return e.reason }
func (e *backendRefusalError) Unwrap() error { return e.cause }

func backendRefuse(kind backendRefusalKind, reason string) error {
	return &backendRefusalError{kind: kind, reason: reason}
}

func (k backendRefusalKind) status() int {
	switch k {
	case backendRefusalQuota:
		return http.StatusTooManyRequests
	case backendRefusalInvalid:
		return http.StatusBadRequest
	case backendRefusalNotFound:
		return http.StatusNotFound
	case backendRefusalInternal:
		return http.StatusInternalServerError
	}
	return 529
}

func (k backendRefusalKind) errorType() string {
	switch k {
	case backendRefusalQuota:
		return "rate_limit_error"
	case backendRefusalInvalid:
		return "invalid_request_error"
	case backendRefusalNotFound:
		return "not_found_error"
	case backendRefusalInternal:
		return "api_error"
	}
	return "overloaded_error"
}

// backendUpstreamError is one upstream error response, kept exactly as received.
type backendUpstreamError struct {
	status  int
	headers http.Header
	body    []byte
}

type backendUpstreamResponseError interface {
	StatusCode() int
	ResponseHeaders() http.Header
	ResponseBody() []byte
}

// noteBackendUpstreamError keeps the latest upstream error response of this request (the last
// one wins: it is the one the scheduler acted on last).
func noteBackendUpstreamError(ctx context.Context, err error) {
	noteBackendUpstreamErrorFor(ctx, "", "", err)
}

func noteBackendUpstreamErrorFor(ctx context.Context, authID, model string, err error) {
	if err == nil {
		return
	}
	var upstream backendUpstreamResponseError
	if !errors.As(err, &upstream) || upstream == nil {
		return
	}
	status := upstream.StatusCode()
	if status < 400 || status > 599 {
		return
	}
	record := &backendUpstreamError{status: status, headers: upstream.ResponseHeaders(), body: append([]byte(nil), upstream.ResponseBody()...)}
	rememberBackendUpstreamError(authID, model, record)
	state := backendRequestAttempt(ctx)
	if state == nil {
		return
	}
	state.mu.Lock()
	state.upstream = record
	state.mu.Unlock()
}

// The last upstream error per subscription and model, kept for as long as the cooldown it caused
// can last. A conversation bound to a subscription that answered 404 for its model is refused on
// every later request without an upstream call; Anthropic would answer that 404 again, so the
// session gets it again, exactly, instead of a refusal of the pool's own.
const backendUpstreamMemoryTTL = time.Hour

type backendUpstreamMemoryEntry struct {
	at       time.Time
	upstream *backendUpstreamError
}

var backendUpstreamMemory sync.Map // authID + "\x00" + model -> *backendUpstreamMemoryEntry

func rememberBackendUpstreamError(authID, model string, upstream *backendUpstreamError) {
	if authID == "" || upstream == nil {
		return
	}
	backendUpstreamMemory.Store(authID+"\x00"+backendBlockedModelKey(model), &backendUpstreamMemoryEntry{at: time.Now(), upstream: upstream})
}

func rememberedBackendUpstreamError(authID, model string) *backendUpstreamError {
	if authID == "" {
		return nil
	}
	value, ok := backendUpstreamMemory.Load(authID + "\x00" + backendBlockedModelKey(model))
	if !ok {
		return nil
	}
	entry, _ := value.(*backendUpstreamMemoryEntry)
	if entry == nil || time.Since(entry.at) > backendUpstreamMemoryTTL {
		return nil
	}
	return entry.upstream
}

func backendUpstreamErrorFrom(ctx context.Context) *backendUpstreamError {
	state := backendRequestAttempt(ctx)
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.upstream
}

// backendRecordingExecutor records each upstream error response on the request, whichever
// executor serves it, including one that arrives inside a stream.
type backendRecordingExecutor struct {
	coreauth.ProviderExecutor
}

func withBackendUpstreamRecording(executor coreauth.ProviderExecutor) coreauth.ProviderExecutor {
	if executor == nil {
		return nil
	}
	if _, already := executor.(*backendRecordingExecutor); already {
		return executor
	}
	return &backendRecordingExecutor{ProviderExecutor: executor}
}

func (e *backendRecordingExecutor) Execute(ctx context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	resp, err := e.ProviderExecutor.Execute(ctx, auth, req, opts)
	noteBackendUpstreamErrorFor(ctx, backendAuthID(auth), req.Model, err)
	return resp, err
}

func (e *backendRecordingExecutor) CountTokens(ctx context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	resp, err := e.ProviderExecutor.CountTokens(ctx, auth, req, opts)
	noteBackendUpstreamErrorFor(ctx, backendAuthID(auth), req.Model, err)
	return resp, err
}

func (e *backendRecordingExecutor) ExecuteStream(ctx context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	result, err := e.ProviderExecutor.ExecuteStream(ctx, auth, req, opts)
	authID, model := backendAuthID(auth), req.Model
	noteBackendUpstreamErrorFor(ctx, authID, model, err)
	if err != nil || result == nil || result.Chunks == nil {
		return result, err
	}
	in := result.Chunks
	out := make(chan coreexecutor.StreamChunk)
	go func() {
		defer close(out)
		for chunk := range in {
			if chunk.Err != nil {
				noteBackendUpstreamErrorFor(ctx, authID, model, chunk.Err)
			}
			select {
			case out <- chunk:
			case <-ctx.Done():
				return
			}
		}
	}()
	return &coreexecutor.StreamResult{Headers: result.Headers, Chunks: out}, nil
}

func backendAuthID(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	return auth.ID
}

// writeBackendFailure is every error the session sees when no upstream body is passed through
// by the caller: the request's recorded upstream error exactly as Anthropic sent it; else the
// selector's refusal in Anthropic's error shape; else the generic line (also in that shape).
// headers writes the response headers the way the calling path does (native or protocol).
func writeBackendFailure(ctx context.Context, w http.ResponseWriter, fallbackStatus int, headers func(http.Header, http.Header)) {
	if upstream := backendUpstreamErrorFrom(ctx); upstream != nil {
		headers(w.Header(), upstream.headers)
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(upstream.status)
		_, _ = w.Write(upstream.body)
		return
	}
	var refusal *backendRefusalError
	if err := backendRefusalErrorFrom(ctx); errors.As(err, &refusal) && refusal != nil {
		if remembered := rememberedBackendUpstreamError(refusal.authID, refusal.model); remembered != nil {
			headers(w.Header(), remembered.headers)
			if w.Header().Get("Content-Type") == "" {
				w.Header().Set("Content-Type", "application/json")
			}
			w.WriteHeader(remembered.status)
			_, _ = w.Write(remembered.body)
			return
		}
		if refusal.kind == backendRefusalQuota {
			writeBackendQuotaHeaders(w.Header(), refusal.resetAt)
		}
		w.Header().Set("Claude-Master-Reason", refusal.reason)
		backendAnthropicError(w, refusal.kind.status(), refusal.kind.errorType(), backendRefusalMessage(refusal))
		return
	}
	if reason := backendRefusal(ctx); reason != "" {
		backendAnthropicError(w, fallbackStatus, "api_error", "claude-master: "+reason)
		return
	}
	backendAnthropicError(w, fallbackStatus, "api_error", "Configured inference failed; no fallback to the native master was attempted")
}

// backendRefusalMessage: a quota refusal carries Anthropic's own rate-limit text, so the client
// shows what it shows for Anthropic's 429 (the reason is in the Claude-Master-Reason header);
// every other kind names the reason, because Anthropic's own texts for those vary anyway.
func backendRefusalMessage(refusal *backendRefusalError) string {
	if refusal.kind == backendRefusalQuota {
		return "This request would exceed your account's rate limit. Please try again later."
	}
	return "claude-master: " + refusal.reason
}

// writeBackendQuotaHeaders: the headers Anthropic sends with a weekly-quota 429 (observed
// 2026-10-09), so the client's retry and "resets at" behave as they do for Anthropic.
func writeBackendQuotaHeaders(dst http.Header, resetAt time.Time) {
	dst.Set("X-Should-Retry", "true")
	dst.Set("Anthropic-Ratelimit-Unified-Status", "rejected")
	dst.Set("Anthropic-Ratelimit-Unified-7d-Status", "rejected")
	dst.Set("Anthropic-Ratelimit-Unified-7d-Utilization", "1.0")
	dst.Set("Anthropic-Ratelimit-Unified-Representative-Claim", "seven_day")
	if resetAt.IsZero() {
		return
	}
	epoch := strconv.FormatInt(resetAt.Unix(), 10)
	dst.Set("Anthropic-Ratelimit-Unified-Reset", epoch)
	dst.Set("Anthropic-Ratelimit-Unified-7d-Reset", epoch)
	if wait := time.Until(resetAt); wait > 0 {
		dst.Set("Retry-After", strconv.FormatInt(int64(wait/time.Second)+1, 10))
	}
}

func backendAnthropicError(w http.ResponseWriter, status int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":%q,"message":%q}}`, errorType, message)
}

// earliestResetLocked: when the first of the pool's subscriptions gets its weekly quota back.
func (s *backendSeriesSelector) earliestResetLocked() time.Time {
	var earliest time.Time
	for _, authID := range s.authIDs {
		candidates := []time.Time{s.currentQuotaLocked(authID).resetsAt}
		if until, blocked := s.quotaBlockedUntil[authID]; blocked {
			candidates = append(candidates, until)
		}
		for _, at := range candidates {
			if !at.IsZero() && (earliest.IsZero() || at.Before(earliest)) {
				earliest = at
			}
		}
	}
	return earliest
}

func (s *backendSeriesSelector) quotaRefusalLocked(reason string) error {
	return &backendRefusalError{kind: backendRefusalQuota, reason: reason, resetAt: s.earliestResetLocked()}
}

var _ = strings.TrimSpace
var _ sync.Mutex
