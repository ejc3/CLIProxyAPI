package claudemaster

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const hookSettingsFixture = `{"preferredNotifChannel":"notifications_disabled","hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"/private/session-sync.sh","timeout":90}]}],"Notification":[{"hooks":[{"type":"command","command":"/private/notify.sh","timeout":10}]}]}}`

func TestNativeHookSettingsImmutableSnapshot(t *testing.T) {
	file := filepath.Join(canonicalTestTempDir(t), "hooks.json")
	if err := os.WriteFile(file, []byte(hookSettingsFixture), 0o600); err != nil { t.Fatal(err) }
	for _, args := range [][]string{{"--settings", file, "--remote-control"}, {"--settings=" + file}, {"--settings", hookSettingsFixture}} {
		original := append([]string(nil), args...)
		got, err := snapshotNativeHookSettings(args)
		if err != nil { t.Fatal(err) }
		if !reflect.DeepEqual(original, args) { t.Fatal("caller arguments mutated") }
		if strings.Contains(strings.Join(got, " "), file) { t.Fatal("mutable file passed to native") }
		if _, err := ChildEnvironment(nil, got, "proxy", "ca"); err != nil { t.Fatal(err) }
		if !strings.Contains(strings.Join(got, " "), "session-sync.sh") { t.Fatal("session tracking hook lost") }
	}
	got, err := snapshotNativeHookSettings([]string{"--settings", file})
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(file, []byte(`{"env":{"NO_PROXY":"*"}}`), 0o600); err != nil { t.Fatal(err) }
	if _, err := ChildEnvironment(nil, got, "proxy", "ca"); err != nil { t.Fatal("snapshot changed with source", err) }
	if _, err := ChildEnvironment(nil, []string{"--settings", file}, "proxy", "ca"); err == nil { t.Fatal("environment boundary accepted mutable file") }
}

func TestNativeHookSettingsRejectUnsafeSourcesAndOverrides(t *testing.T) {
	for _, value := range []string{`{"env":{"NO_PROXY":"secret-canary"}}`, `{"apiKeyHelper":"secret-canary"}`, `{"permissions":{}}`, `{"model":"other"}`, `null`, `[]`, `{"hooks":null}`, `{"hooks":[]}`, `{"preferredNotifChannel":null}`, `{"preferredNotifChannel":{}}`, `{broken`, `{"hooks":{},"env":{},"hooks":{}}`} {
		if _, err := snapshotNativeHookSettings([]string{"--settings", value}); err == nil || strings.Contains(err.Error(), "secret-canary") {
			t.Fatalf("settings accepted or leaked: %v", err)
		}
	}
	for _, args := range [][]string{{"--settings"}, {"--settings="}, {"--settings", "{}", "--settings={}"}} {
		if _, err := snapshotNativeHookSettings(args); err == nil { t.Fatal("invalid settings arguments accepted") }
	}
	for _, kind := range []string{"symlink", "fifo", "directory", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			file := filepath.Join(canonicalTestTempDir(t), "hooks")
			var err error
			switch kind {
			case "symlink": err = os.Symlink("missing", file)
			case "fifo": err = unix.Mkfifo(file, 0o600)
			case "directory": err = os.Mkdir(file, 0o700)
			case "oversized": err = os.WriteFile(file, []byte(strings.Repeat(" ", hookSettingsByteLimit+1)), 0o600)
			}
			if err != nil { t.Fatal(err) }
			if _, err := snapshotNativeHookSettings([]string{"--settings", file}); err == nil { t.Fatal("unsafe source accepted") }
		})
	}
}

func TestNativeHookSettingsRespectsArgumentTerminator(t *testing.T) {
	args := []string{"--", "--settings=prompt-text"}
	got, err := snapshotNativeHookSettings(args)
	if err != nil || !reflect.DeepEqual(got, args) { t.Fatalf("prompt changed: %v %v", got, err) }
	if _, err := ChildEnvironment(nil, got, "proxy", "ca"); err != nil { t.Fatal(err) }
}
