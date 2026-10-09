package claudemaster

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// The person sees why claude-master refused, in claude-master's own words; an upstream error
// still gets the generic line and never its text.
func TestClientErrorNamesTheSelectorsRefusal(t *testing.T) {
	ctx := withBackendAttempt(context.Background())
	noteBackendRefusal(ctx, &coreauth.Error{Code: "auth_unavailable", Message: "no auth available"})
	noteBackendRefusal(ctx, errors.New("subscription alpha does not serve model claude-test-model (HTTP 404)"))
	noteBackendRefusal(ctx, errors.New("a later, vaguer reason"))
	noteBackendRefusal(ctx, &coreauth.Error{Code: "auth_unavailable", Message: "no auth available"})
	for name, write := range map[string]func(context.Context, http.ResponseWriter, *interfaces.ErrorMessage){"protocol": writeBackendUpstreamError, "native": writeBackendNativeUpstreamError} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			write(ctx, w, &interfaces.ErrorMessage{StatusCode: 503, Error: errors.New("private-upstream-error")})
			body := w.Body.String()
			if w.Code != 503 || !strings.Contains(body, "claude-master: subscription alpha does not serve model claude-test-model (HTTP 404)") {
				t.Fatalf("refusal not surfaced: %d %s", w.Code, body)
			}
			if strings.Contains(body, "later, vaguer") || strings.Contains(body, "no auth available") || strings.Contains(body, "private-upstream-error") || strings.Contains(body, "Configured inference failed") {
				t.Fatalf("wrong text in the client error: %s", body)
			}
			plain := httptest.NewRecorder()
			write(withBackendAttempt(context.Background()), plain, &interfaces.ErrorMessage{StatusCode: 502, Error: errors.New("private-upstream-error")})
			if !strings.Contains(plain.Body.String(), "Configured inference failed") || strings.Contains(plain.Body.String(), "private-upstream-error") {
				t.Fatalf("a request with no refusal must get the generic line: %s", plain.Body.String())
			}
		})
	}
}

// The outage of 2026-10-09: a conversation bound to a subscription that answered 404 for its
// model was refused with "the current Claude subscription is unavailable", which reads like an
// outage. The refusal now names the subscription, the model, the status and the way out.
func TestBoundSubscriptionRefusalNamesModelAndStatus(t *testing.T) {
	selector := &backendSeriesSelector{authIDs: []string{"profile-a", "profile-b"}, provider: "claude", names: map[string]string{"profile-a": "alpha"}}
	t.Cleanup(selector.Stop)
	authA := backendSeriesTestAuth("profile-a", "claude")
	authB := backendSeriesTestAuth("profile-b", "claude")
	headers := http.Header{"X-Claude-Code-Session-Id": []string{"session-404"}}
	ctx := withBackendAttempt(context.Background())
	if _, err := selector.Pick(ctx, "claude", "claude-test-model", coreexecutor.Options{
		Headers: headers, OriginalRequest: []byte(`{"model":"claude-test-model","messages":[{"role":"user","content":"start"}]}`),
	}, []*coreauth.Auth{authA, authB}); err != nil {
		t.Fatal(err)
	}
	recordBackendAttempt(ctx, coreauth.Result{AuthID: "profile-a", Model: "claude-test-model", Error: &coreauth.Error{HTTPStatus: http.StatusNotFound, Message: "private-upstream-text"}})
	got, err := selector.Pick(ctx, "claude", "claude-test-model", coreexecutor.Options{
		Headers: headers, OriginalRequest: []byte(`{"model":"claude-test-model","messages":[{"role":"user","content":"start"},{"role":"assistant","content":[{"type":"text","text":"hi"}]},{"role":"user","content":"more"}]}`),
	}, []*coreauth.Auth{authB})
	if err == nil || got != nil {
		t.Fatalf("an upstream 404 must not move the conversation: got %#v", got)
	}
	msg := err.Error()
	for _, want := range []string{"subscription alpha", "claude-test-model", "404", "/model"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "private-upstream-text") || strings.Contains(msg, "profile-a") {
		t.Fatalf("refusal leaks upstream text or the runtime id: %s", msg)
	}
	if backendRefusal(ctx) != msg {
		t.Fatalf("the refusal was not recorded for the client's error: %q", backendRefusal(ctx))
	}
}
