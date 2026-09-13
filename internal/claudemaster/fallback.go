package claudemaster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
)

// MaxFallbackProfiles bounds independently authenticated accounts in one run.
const MaxFallbackProfiles = 16

// FallbackBackend advances through explicitly selected profiles only when the
// provider confirms credential-wide quota exhaustion. The order is sticky for
// this run: a depleted account is never retried, even after its quota resets.
// The caller must hold every profile lock and join proxy handlers before Close.
type FallbackBackend struct {
	lifetime context.Context
	cancel   context.CancelFunc
	backends []*Backend
	handlers []http.Handler
	mu       sync.Mutex
	index    int
	terminal http.Header
	onChange func(int, int)
	once     sync.Once
}

// NewFallbackBackend validates all candidates before starting refresh workers.
// A chain cannot silently change provider or model, and duplicate credential
// filenames are rejected because the SDK's model registry keys by AuthID.
func NewFallbackBackend(ctx context.Context, options []BackendOptions) (*FallbackBackend, error) {
	if ctx == nil {
		return nil, errors.New("fallback backend requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(options) == 0 || len(options) > MaxFallbackProfiles {
		return nil, errors.New("inference requires between one and sixteen ordered profiles")
	}
	seen := make(map[string]bool, len(options))
	for _, opts := range options {
		if opts.Provider != options[0].Provider || opts.Model != options[0].Model {
			return nil, errors.New("fallback profiles must use the same provider and model")
		}
		if seen[opts.AuthID] {
			return nil, errors.New("fallback profiles must have distinct credential identities")
		}
		seen[opts.AuthID] = true
		if _, err := backendModel(opts); err != nil {
			return nil, err
		}
		if _, _, err := loadBackendCredential(ctx, opts); err != nil {
			return nil, err
		}
	}
	lifetime, cancel := context.WithCancel(ctx)
	b := &FallbackBackend{lifetime: lifetime, cancel: cancel}
	for _, opts := range options {
		backend, err := NewBackend(lifetime, opts)
		if err != nil {
			_ = b.Close()
			return nil, err
		}
		b.backends = append(b.backends, backend)
		b.handlers = append(b.handlers, backend.Handler())
	}
	return b, nil
}

func (b *FallbackBackend) Handler() http.Handler { return b }

// SetOnFallback installs a privacy-safe notification of a committed transition.
// Indices address the supplied profile list, never raw provider/account errors.
// Callbacks must be concurrency-safe and should not block inference.
func (b *FallbackBackend) SetOnFallback(callback func(fromIndex, toIndex int)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onChange = callback
}

func (b *FallbackBackend) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		b.cancel()
		for index := len(b.backends) - 1; index >= 0; index-- {
			_ = b.backends[index].Close()
		}
	})
	return nil
}

func (b *FallbackBackend) current() (int, http.Header) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.index, b.terminal.Clone()
}

func (b *FallbackBackend) exhaust(index int, headers http.Header) {
	b.mu.Lock()
	if b.index != index {
		b.mu.Unlock()
		return
	}
	b.index++
	next, callback := b.index, b.onChange
	if next == len(b.handlers) {
		b.terminal = make(http.Header)
		writeBackendProtocolHeaders(b.terminal, headers)
	}
	b.mu.Unlock()
	if next < len(b.handlers) && callback != nil {
		callback(index, next)
	}
}

func (b *FallbackBackend) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(b.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if b.lifetime.Err() != nil || ctx.Err() != nil {
		observeBackendStage(request.Context(), BackendErrorClosed)
		backendError(w, http.StatusServiceUnavailable, "inference backend is closed")
		return
	}
	// Only inference routes may use this finite replay mechanism. In particular,
	// native control-plane requests can never be retried under another account.
	if request.Method != http.MethodPost || (request.URL.Path != "/v1/messages" && request.URL.Path != "/v1/messages/count_tokens") {
		http.NotFound(w, request)
		return
	}
	if request.Body == nil {
		observeBackendStage(request.Context(), BackendErrorRequest)
		backendError(w, http.StatusBadRequest, "invalid inference request")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, backendMaxBodyBytes+1))
	if err != nil || len(raw) > backendMaxBodyBytes {
		observeBackendStage(request.Context(), BackendErrorRequest)
		backendError(w, http.StatusBadRequest, "invalid inference request")
		return
	}
	for {
		if ctx.Err() != nil {
			observeBackendStage(request.Context(), BackendErrorCanceled)
			return
		}
		index, terminal := b.current()
		if index == len(b.handlers) {
			observeBackendStage(request.Context(), BackendErrorUpstreamHTTP)
			writeBackendProtocolHeaders(w.Header(), terminal)
			backendError(w, http.StatusTooManyRequests, "All configured inference profiles have exhausted their subscription quota; start a new run after quota resets")
			return
		}
		// Each attempt gets an immutable request snapshot and its own diagnostic
		// observation. A successfully recovered rejection is not the final error.
		observation := &backendErrorObservation{}
		attemptCtx := context.WithValue(ctx, backendErrorObservationKey{}, observation)
		attempt := request.Clone(attemptCtx)
		attempt.Body = io.NopCloser(bytes.NewReader(raw))
		attempt.ContentLength = int64(len(raw))
		writer := &fallbackResponseWriter{underlying: w, header: make(http.Header), observation: observation}
		b.handlers[index].ServeHTTP(writer, attempt)
		if !observation.quotaExhausted() || ctx.Err() != nil {
			observeBackendStage(request.Context(), observation.result())
			return
		}
		b.exhaust(index, writer.Header())
		if writer.committed {
			// Even a heartbeat, an empty flush, or a failed write is a commit
			// boundary. Never duplicate generated output or tool execution.
			observeBackendStage(request.Context(), observation.result())
			return
		}
	}
}

// This accepts only the executor's typed quota classification, not status 429
// alone, retry headers, auth_unavailable, or prose in a provider's error body.
// Claude sets the marker for unified account limits; Codex sets it only for
// usage_limit_reached. RPM/TPM throttling and request entitlements are excluded.
func backendQuotaExhausted(message *interfaces.ErrorMessage) bool {
	if message == nil || message.StatusCode != http.StatusTooManyRequests || message.Error == nil {
		return false
	}
	var requestScoped interface{ IsRequestScoped() bool }
	if errors.As(message.Error, &requestScoped) && requestScoped.IsRequestScoped() {
		return false
	}
	var credentialScoped interface{ IsCredentialScoped() bool }
	return errors.As(message.Error, &credentialScoped) && credentialScoped.IsCredentialScoped()
}

func (o *backendErrorObservation) quotaExhausted() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.quota
}

// Ordinary responses stream directly. Only a positively classified quota error
// before the first write is suppressed; no generated response is buffered.
type fallbackResponseWriter struct {
	underlying  http.ResponseWriter
	header      http.Header
	observation *backendErrorObservation
	committed   bool
}

func (w *fallbackResponseWriter) Header() http.Header { return w.header }

func (w *fallbackResponseWriter) commit(status int) {
	if w.committed {
		return
	}
	w.committed = true
	for key, values := range w.header {
		w.underlying.Header()[key] = append([]string(nil), values...)
	}
	w.underlying.WriteHeader(status)
}

func (w *fallbackResponseWriter) WriteHeader(status int) {
	if !w.committed && w.observation.quotaExhausted() {
		return
	}
	w.commit(status)
}

func (w *fallbackResponseWriter) Write(data []byte) (int, error) {
	if !w.committed && w.observation.quotaExhausted() {
		return len(data), nil
	}
	w.commit(http.StatusOK)
	return w.underlying.Write(data)
}

func (w *fallbackResponseWriter) Flush() {
	w.commit(http.StatusOK)
	if flusher, ok := w.underlying.(http.Flusher); ok {
		flusher.Flush()
	}
}
