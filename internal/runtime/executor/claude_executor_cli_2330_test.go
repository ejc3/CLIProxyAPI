package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Claude Code 2.1.330, measured 2026-11-23 (a request to a local listener): User-Agent
// claude-cli/2.1.330, X-Stainless-Package-Version 0.128.0, X-Stainless-Runtime-Version v26.12.1.
// A confirmed client on it reaches Anthropic as itself: its User-Agent with the SDK and runtime it
// really runs, never a newer CLI claiming an older SDK.
func TestClaudeExecutor_ConfirmedCLI2330KeepsItsMeasuredSoftwareProfile(t *testing.T) {
	helps.ResetClaudeDeviceProfileCache()
	var seen http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-5-5","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()
	const userAgent = "claude-cli/2.1.330 (external, cli)"
	billing := "x-anthropic-billing-header: cc_version=2.1.330.d7b; cc_entrypoint=cli; cch=00000; cc_turn_origin=human;"
	userID := `{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","account_uuid":"11111111-2222-4333-8444-555555555555","session_id":"11111111-2222-4333-8444-555555555555"}`
	payload := []byte(`{"model":"claude-opus-5-5","system":[{"type":"text","text":` + fmt.Sprintf("%q", billing) + `},{"type":"text","text":"native identity"}],"messages":[{"role":"user","content":"hello"}],"metadata":{"user_id":` + fmt.Sprintf("%q", userID) + `}}`)
	incoming := http.Header{
		"User-Agent": {userAgent}, "X-App": {"cli"},
		"Anthropic-Beta":              {"claude-code-20250219,oauth-2025-04-20"},
		"X-Claude-Code-Session-Id":    {"11111111-2222-4333-8444-555555555555"},
		"X-Stainless-Package-Version": {"0.128.0"}, "X-Stainless-Runtime-Version": {"v26.12.1"},
		"X-Stainless-Lang": {"js"}, "X-Stainless-Runtime": {"node"}, "X-Stainless-Os": {"Linux"}, "X-Stainless-Arch": {"arm64"},
		"Anthropic-Dangerous-Direct-Browser-Access": {"true"},
	}
	if detection := helps.DetectClaudeCodeRequest(incoming, payload, false); !detection.Confirmed {
		t.Fatalf("fixture must be classified as a native CLI request: %+v", detection)
	}
	auth := &cliproxyauth.Auth{ID: "cli-2330", Metadata: claudeOAuthTestMetadata(), Attributes: map[string]string{"api_key": "sk-ant-oat-cli-2330", "base_url": server.URL}}
	if _, err := NewClaudeExecutor(&config.Config{}).Execute(context.Background(), auth, cliproxyexecutor.Request{Model: "claude-opus-5-5", Payload: payload},
		cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, OriginalRequest: payload, Headers: incoming}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"User-Agent": userAgent, "X-Stainless-Package-Version": "0.128.0", "X-Stainless-Runtime-Version": "v26.12.1"} {
		if got := seen.Get(name); got != want {
			t.Errorf("upstream %s = %q, want %q", name, got, want)
		}
	}
}
