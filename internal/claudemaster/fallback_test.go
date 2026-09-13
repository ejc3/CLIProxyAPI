package claudemaster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type fallbackTestError struct {
	status     int
	credential bool
	request    bool
}

func (e fallbackTestError) Error() string { return "PRIVATE-QUOTA-ERROR-CANARY" }
func (e fallbackTestError) StatusCode() int { return e.status }
func (e fallbackTestError) IsCredentialScoped() bool { return e.credential }
func (e fallbackTestError) IsRequestScoped() bool { return e.request }
func (e fallbackTestError) Headers() http.Header {
	return http.Header{"Retry-After": {"3600"}, "Anthropic-Ratelimit-Unified-Status": {"rejected"}, "Set-Cookie": {"PRIVATE-QUOTA-ERROR-CANARY"}}
}

func fallbackTestQuota() error { return fallbackTestError{status: 429, credential: true} }

func TestBackendQuotaExhaustedRequiresTypedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		message *interfaces.ErrorMessage
		want bool
	}{
		{"missing", nil, false},
		{"ordinary429", &interfaces.ErrorMessage{StatusCode: 429, Error: fallbackTestError{status: 429}}, false},
		{"confirmed", &interfaces.ErrorMessage{StatusCode: 429, Error: fallbackTestQuota()}, true},
		{"wrapped", &interfaces.ErrorMessage{StatusCode: 429, Error: fmt.Errorf("wrapped: %w", fallbackTestQuota())}, true},
		{"request-entitlement", &interfaces.ErrorMessage{StatusCode: 429, Error: fallbackTestError{status: 429, credential: true, request: true}}, false},
		{"wrong-status", &interfaces.ErrorMessage{StatusCode: 401, Error: fallbackTestError{status: 401, credential: true}}, false},
		{"header-not-evidence", &interfaces.ErrorMessage{StatusCode: 429, Error: errors.New("usage_limit_reached"), Addon: http.Header{"Anthropic-Ratelimit-Unified-Status": {"rejected"}}}, false},
		{"cooldown-not-evidence", &interfaces.ErrorMessage{StatusCode: 429, Error: &coreauth.Error{Code: "auth_unavailable", HTTPStatus: 429}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := backendQuotaExhausted(tc.message); got != tc.want { t.Fatalf("quota=%t want=%t", got, tc.want) }
		})
	}
}

func fallbackTestChain(t *testing.T, executors ...coreauth.ProviderExecutor) *FallbackBackend {
	t.Helper()
	lifetime, cancel := context.WithCancel(t.Context())
	b := &FallbackBackend{lifetime: lifetime, cancel: cancel}
	for index, executor := range executors {
		opts := BackendOptions{Provider: "codex", Model: t.Name()+"-model", AuthID: fmt.Sprintf("%s-profile-%d", t.Name(), index)}
		manager := coreauth.NewManager(nil, &backendSelector{authID: opts.AuthID, provider: opts.Provider}, nil)
		manager.SetRetryConfig(0, 0, 1)
		manager.RegisterExecutor(executor)
		registry.GetGlobalRegistry().RegisterClient(opts.AuthID, opts.Provider, []*registry.ModelInfo{{ID: opts.Model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(opts.AuthID) })
		if _, err := manager.Register(t.Context(), &coreauth.Auth{ID: opts.AuthID, Provider: opts.Provider, Status: coreauth.StatusActive}); err != nil { t.Fatal(err) }
		base := handlers.NewBaseAPIHandlers(&config.SDKConfig{PassthroughHeaders: true}, manager)
		b.handlers = append(b.handlers, newBackendHandler(lifetime, opts, base))
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func fallbackTestRequest(path string, stream bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(fmt.Sprintf(`{"model":"master-model","stream":%t,"metadata":{"user_id":"PRIVATE-MASTER-CANARY"},"messages":[{"role":"user","content":"preserve this prompt"}]}`, stream)))
	r.Header = nativeProtocolFixture()
	r.Header.Set("Authorization", "Bearer PRIVATE-MASTER-CANARY")
	return r
}

func TestFallbackBackendPinsAndAdvancesEveryInferenceRoute(t *testing.T) {
	for _, tc := range []struct { path string; stream bool }{{"/v1/messages", false}, {"/v1/messages", true}, {"/v1/messages/count_tokens", false}} {
		t.Run(fmt.Sprintf("%s-%t", tc.path, tc.stream), func(t *testing.T) {
			first, second, third := &backendCapture{err: fallbackTestQuota()}, &backendCapture{err: fallbackTestQuota()}, &backendCapture{}
			b := fallbackTestChain(t, first, second, third)
			var transitions [][2]int
			b.SetOnFallback(func(from, to int) { transitions = append(transitions, [2]int{from,to}) })
			observation := &backendErrorObservation{}
			ctx := context.WithValue(t.Context(), backendErrorObservationKey{}, observation)
			for request := 0; request < 2; request++ {
				w := httptest.NewRecorder()
				b.ServeHTTP(w, fallbackTestRequest(tc.path, tc.stream).WithContext(ctx))
				if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE-") || w.Header().Get("Retry-After") != "" { t.Fatalf("failed recovery: %d %s headers=%v", w.Code, w.Body.String(), w.Header()) }
			}
			if first.calls != 1 || second.calls != 1 || third.calls != 2 { t.Fatalf("wrong attempts: %d %d %d", first.calls, second.calls, third.calls) }
			if !reflect.DeepEqual(transitions, [][2]int{{0,1},{1,2}}) { t.Fatalf("wrong transitions: %v", transitions) }
			if observation.result() != BackendErrorNone { t.Fatal("recovered error tainted final diagnostics") }
			for index, capture := range []*backendCapture{first,second,third} {
				if capture.authID != fmt.Sprintf("%s-profile-%d", t.Name(), index) || capture.opts.Metadata[coreexecutor.PinnedAuthMetadataKey] != capture.authID { t.Fatal("fallback escaped pinned credential") }
				if !strings.Contains(string(capture.req.Payload), "preserve this prompt") || strings.Contains(string(capture.req.Payload), "PRIVATE-") || capture.opts.Headers.Get("Authorization") != "" { t.Fatal("fallback damaged content or leaked master identity") }
				if !reflect.DeepEqual(capture.opts.Headers.Values("Anthropic-Beta"), nativeProtocolFixture().Values("Anthropic-Beta")) { t.Fatal("native protocol headers changed during fallback") }
			}
		})
	}
}

func TestFallbackBackendDoesNotRotateOnOtherFailures(t *testing.T) {
	for _, tc := range []struct { name string; err error }{
		{"throttle", fallbackTestError{status: 429}},
		{"entitlement", fallbackTestError{status: 429, request: true}},
		{"auth", fallbackTestError{status: 401}},
		{"forbidden", fallbackTestError{status: 403}},
		{"server", fallbackTestError{status: 503}},
		{"transport", errors.New("PRIVATE-TRANSPORT-CANARY")},
		{"cooldown", &coreauth.Error{Code: "auth_unavailable", HTTPStatus: 503}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, second := &backendCapture{err: tc.err}, &backendCapture{}
			b := fallbackTestChain(t, first, second)
			w := httptest.NewRecorder()
			b.ServeHTTP(w, fallbackTestRequest("/v1/messages", false))
			if first.calls != 1 || second.calls != 0 || w.Code < 400 || strings.Contains(w.Body.String(), "PRIVATE-") { t.Fatalf("unexpected fallback: calls=%d/%d status=%d", first.calls, second.calls, w.Code) }
			if index, _ := b.current(); index != 0 { t.Fatal("non-quota failure advanced the chain") }
		})
	}
}

func TestFallbackBackendRemembersAllExhausted(t *testing.T) {
	first, second := &backendCapture{err: fallbackTestQuota()}, &backendCapture{err: fallbackTestQuota()}
	b := fallbackTestChain(t, first, second)
	for request := 0; request < 3; request++ {
		w := httptest.NewRecorder()
		b.ServeHTTP(w, fallbackTestRequest("/v1/messages", false))
		if w.Code != 429 || !strings.Contains(w.Body.String(), "All configured inference profiles") || w.Header().Get("Retry-After") != "3600" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "PRIVATE-") { t.Fatalf("bad exhausted response: %d %s %v", w.Code, w.Body.String(), w.Header()) }
	}
	if first.calls != 1 || second.calls != 1 { t.Fatal("exhausted account retried after SDK cooldown") }
}

type fallbackLateQuotaExecutor struct {
	backendCapture
	committed <-chan struct{}
}

func (e *fallbackLateQuotaExecutor) ExecuteStream(ctx context.Context, auth *coreauth.Auth, request coreexecutor.Request, options coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.record(auth,request,options)
	chunks := make(chan coreexecutor.StreamChunk)
	go func() {
		defer close(chunks)
		select {
		case chunks <- coreexecutor.StreamChunk{Payload: []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"already-generated\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"model\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n")}:
		case <-ctx.Done(): return
		}
		select { case <-e.committed: case <-ctx.Done(): return }
		select { case chunks <- coreexecutor.StreamChunk{Err: fallbackTestQuota()}: case <-ctx.Done(): }
	}()
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

type fallbackFlushRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
	once sync.Once
}

func (w *fallbackFlushRecorder) Flush() {
	w.ResponseRecorder.Flush()
	w.once.Do(func() { close(w.flushed) })
}

func TestFallbackBackendNeverReplaysCommittedStream(t *testing.T) {
	flushed := make(chan struct{})
	first, second := &fallbackLateQuotaExecutor{committed: flushed}, &backendCapture{}
	b := fallbackTestChain(t, first, second)
	w := &fallbackFlushRecorder{ResponseRecorder: httptest.NewRecorder(), flushed: flushed}
	b.ServeHTTP(w, fallbackTestRequest("/v1/messages", true))
	if first.calls != 1 || second.calls != 0 || !strings.Contains(w.Body.String(), "already-generated") || !strings.Contains(w.Body.String(), "event: error") { t.Fatalf("committed stream replayed or lost: %d/%d %s", first.calls, second.calls, w.Body.String()) }
	if index, _ := b.current(); index != 1 { t.Fatal("confirmed late quota did not advance future requests") }
	next := httptest.NewRecorder()
	b.ServeHTTP(next, fallbackTestRequest("/v1/messages", false))
	if next.Code != 200 || second.calls != 1 { t.Fatal("next request did not use fallback after late quota") }
}

func TestFallbackWriterFlushAndFailedWriteAreCommitBoundaries(t *testing.T) {
	for _, kind := range []string{"flush", "header", "failed-write"} {
		t.Run(kind, func(t *testing.T) {
			observation := &backendErrorObservation{}
			var underlying http.ResponseWriter = httptest.NewRecorder()
			if kind == "failed-write" { underlying = &fallbackFailedWriter{header: make(http.Header)} }
			w := &fallbackResponseWriter{underlying: underlying, header: make(http.Header), observation: observation}
			switch kind { case "flush": w.Flush(); case "header": w.WriteHeader(200); case "failed-write": _, _ = w.Write([]byte("partial")) }
			observation.quota = true
			if !w.committed { t.Fatal("response boundary was not committed") }
		})
	}
}

type fallbackFailedWriter struct { header http.Header }
func (w *fallbackFailedWriter) Header() http.Header { return w.header }
func (w *fallbackFailedWriter) WriteHeader(int) {}
func (w *fallbackFailedWriter) Write([]byte) (int,error) { return 0,io.ErrClosedPipe }

func TestFallbackBackendCancellationDoesNotReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var next atomic.Int32
	b := &FallbackBackend{lifetime: t.Context(), cancel: func(){}}
	b.handlers = []http.Handler{
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observeBackendError(r.Context(), &interfaces.ErrorMessage{StatusCode: 429,Error: fallbackTestQuota()})
			cancel()
			writeBackendUpstreamError(w,&interfaces.ErrorMessage{StatusCode: 429,Error: fallbackTestQuota()})
		}),
		http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) { next.Add(1) }),
	}
	b.ServeHTTP(httptest.NewRecorder(), fallbackTestRequest("/v1/messages",false).WithContext(ctx))
	if next.Load()!=0 { t.Fatal("canceled request retried") }
}

func TestFallbackBackendConcurrentExhaustionTransitionsOnlyOnce(t *testing.T) {
	const requests=12
	started,release := make(chan struct{},requests),make(chan struct{})
	var next,notices atomic.Int32
	b := &FallbackBackend{lifetime:t.Context(), cancel:func(){}}
	b.handlers=[]http.Handler{
		http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
			started<-struct{}{}
			<-release
			message:=&interfaces.ErrorMessage{StatusCode:429,Error:fallbackTestQuota()}
			observeBackendError(r.Context(),message)
			writeBackendUpstreamError(w,message)
		}),
		http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) { next.Add(1); _,_=io.WriteString(w,"success") }),
	}
	b.SetOnFallback(func(from,to int) { if from!=0 || to!=1 { t.Error("incorrect concurrent transition") };notices.Add(1) })
	var done sync.WaitGroup
	for i:=0;i<requests;i++ { done.Go(func(){ w:=httptest.NewRecorder();b.ServeHTTP(w,fallbackTestRequest("/v1/messages",false));if w.Code!=200 || w.Body.String()!="success" { t.Errorf("concurrent recovery failed: %d %s",w.Code,w.Body.String()) } }) }
	for i:=0;i<requests;i++ { <-started }
	close(release)
	done.Wait()
	if notices.Load()!=1 || next.Load()!=requests { t.Fatalf("transitions=%d recovered=%d",notices.Load(),next.Load()) }
}

func TestNewFallbackBackendPreflightsEveryProfile(t *testing.T) {
	first:=writeSyntheticBackendCredential(t,t.TempDir(),"first.json",nil)
	second:=writeSyntheticBackendCredential(t,t.TempDir(),"second.json",nil)
	for _,tc:=range []struct{name string; options []BackendOptions}{
		{"empty",nil},
		{"duplicate",[]BackendOptions{first,first}},
		{"mixed-provider",[]BackendOptions{first,{Provider:"claude",Model:first.Model,AuthID:"other.json"}}},
		{"mixed-model",[]BackendOptions{first,{Provider:first.Provider,Model:"different",AuthID:"other.json"}}},
		{"invalid-later",[]BackendOptions{first,{Provider:first.Provider,Model:first.Model,AuthID:"missing.json",AuthDir:second.AuthDir}}},
	} {
		t.Run(tc.name,func(t *testing.T){if backend,err:=NewFallbackBackend(t.Context(),tc.options);err==nil {_=backend.Close();t.Fatal("unsafe chain accepted")}})
	}
	b,err:=NewFallbackBackend(t.Context(),[]BackendOptions{first,second})
	if err!=nil { t.Fatal(err) }
	if err:=b.Close();err!=nil { t.Fatal(err) }
	if err:=b.Close();err!=nil { t.Fatal(err) }
	w:=httptest.NewRecorder()
	b.ServeHTTP(w,fallbackTestRequest("/v1/messages",false))
	if w.Code!=503 { t.Fatal("closed chain accepted inference") }
}
