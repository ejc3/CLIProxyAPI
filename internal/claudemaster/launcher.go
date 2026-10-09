package claudemaster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Launch starts the native master with its existing personal Claude login and a process-only proxy.
// The caller must hold the profile lock until this returns. It never edits Claude configuration.
func Launch(ctx context.Context, profile Profile, args []string) (int, error) {
	return LaunchWithDiagnostics(ctx, profile, args, nil)
}

// LaunchWithDiagnostics optionally emits numeric counters and fixed error-stage labels. It never
// emits proxy credentials, request content, URLs, or account identifiers.
func LaunchWithDiagnostics(ctx context.Context, profile Profile, args []string, diagnostics io.Writer) (int, error) {
	return LaunchProfilesWithDiagnostics(ctx, []Profile{profile}, args, diagnostics)
}

// LaunchProfiles starts the native master with an explicitly ordered series of
// independently authenticated Claude inference profiles.
func LaunchProfiles(ctx context.Context, profiles []Profile, args []string) (int, error) {
	return LaunchProfilesWithDiagnostics(ctx, profiles, args, nil)
}

// LaunchProfilesWithDiagnostics is LaunchProfiles with privacy-safe diagnostics.
// The caller must hold every supplied profile lock until this function returns.
func LaunchProfilesWithDiagnostics(ctx context.Context, profiles []Profile, args []string, diagnostics io.Writer) (int, error) {
	return LaunchProfilesWithOptions(ctx, profiles, args, LaunchOptions{Diagnostics: diagnostics})
}

// LaunchOptions configures process-local inference routing. BackupAPIKey is never
// written to a profile or inherited by the native Claude process.
type LaunchOptions struct {
	BackupAPIKey    string
	BackupAPIKeyEnv string
	ModelMap        map[string]string
	Diagnostics     io.Writer
	// SnapshotInterval is how often the quota snapshot is logged (default 5 minutes, negative: never).
	SnapshotInterval time.Duration
}

// BackupAPIKeyEnvironment is the dedicated optional final-backup credential source.
const BackupAPIKeyEnvironment = "CLAUDE_MASTER_BACKUP_API_KEY"

// ValidateBackupAPIKeyEnv accepts portable shell environment variable names.
func ValidateBackupAPIKeyEnv(name string) error {
	if name == "" {
		return errors.New("backup API key environment variable name is invalid")
	}
	for i, char := range name {
		if char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || i > 0 && char >= '0' && char <= '9' {
			continue
		}
		return errors.New("backup API key environment variable name is invalid")
	}
	return nil
}

func launchEnvironment(environ []string, source string) ([]string, error) {
	if source == "" {
		source = BackupAPIKeyEnvironment
	}
	if err := ValidateBackupAPIKeyEnv(source); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(environ))
	for _, entry := range environ {
		key, _, _ := strings.Cut(entry, "=")
		if key != source && key != BackupAPIKeyEnvironment {
			out = append(out, entry)
		}
	}
	return out, nil
}

// LaunchProfilesWithOptions starts a subscription pool with optional final API-key
// backup and exact model mappings. Callers must hold every profile lock until return.
func LaunchProfilesWithOptions(ctx context.Context, profiles []Profile, args []string, opts LaunchOptions) (int, error) {
	environ, err := launchEnvironment(os.Environ(), opts.BackupAPIKeyEnv)
	if err != nil {
		return 1, err
	}
	diagnostics := opts.Diagnostics
	if len(profiles) == 0 {
		return 1, errors.New("at least one inference profile is required")
	}
	provider := profiles[0].Provider
	locations := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if profile.Provider != provider {
			return 1, errors.New("ordered inference profiles must use one provider")
		}
		location := profile.AuthDir + "\x00" + profile.AuthID
		if _, exists := locations[location]; exists {
			return 1, errors.New("ordered inference profiles must be distinct")
		}
		locations[location] = struct{}{}
	}
	if provider != "claude" {
		return 1, errors.New("native inference run requires Claude subscription profiles")
	}
	args, err = NativeArguments(provider, args)
	if err != nil {
		return 1, err
	}
	bin, err := preflight(ctx, args, environ)
	if err != nil {
		return 1, err
	}
	certs, err := newProcessCertificate()
	if err != nil {
		return 1, err
	}
	defer func() { _ = os.RemoveAll(certs.dir) }()
	backend, err := newInferenceBackend(ctx, profiles, opts)
	if err != nil {
		return 1, errors.New("cannot start selected inference backend; check the profile")
	}
	defer func() { _ = backend.Close() }()
	observation := &backendErrorObservation{}
	inference := backend.Handler()
	if diagnostics != nil {
		inference = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), backendErrorObservationKey{}, observation)
			backend.Handler().ServeHTTP(w, r.WithContext(ctx))
		})
	}
	clientCert, clientKey, err := certs.writeClientCertificate()
	if err != nil {
		return 1, err
	}
	proxy, err := StartProxy(ProxyOptions{
		GetCertificate: certs.getCertificate, Inference: inference,
		ProxyCertificate: certs.proxyServerCertificate, ClientCAs: certs.clientPool(),
	})
	if err != nil {
		return 1, errors.New("cannot start private inference proxy")
	}
	stopDiagnostics := startProxyDiagnostics(proxy, diagnostics)
	defer func() {
		_ = proxy.Close()
		stopDiagnostics()
		if diagnostics != nil {
			_ = json.NewEncoder(diagnostics).Encode(struct {
				BackendErrorStage BackendErrorStage
			}{observation.result()})
		}
	}()
	env, err := ChildEnvironment(environ, args, proxy.URL(), certs.caPath, clientCert, clientKey)
	if err != nil {
		return 1, err
	}
	return runNativeChild(ctx, bin, args, env)
}

// newInferenceBackend opens the profiles as one backend: a single profile, or a quota-aware series.
func newInferenceBackend(ctx context.Context, profiles []Profile, opts LaunchOptions) (*Backend, error) {
	if len(profiles) == 1 && opts.BackupAPIKey == "" {
		profile := profiles[0]
		return NewBackend(ctx, BackendOptions{AuthDir: profile.AuthDir, Provider: profile.Provider, AuthID: profile.AuthID, UseRequestModel: true, ModelMap: opts.ModelMap, Name: profile.Name})
	}
	credentials := make([]BackendCredential, 0, len(profiles))
	for _, profile := range profiles {
		credentials = append(credentials, BackendCredential{AuthDir: profile.AuthDir, Provider: profile.Provider, AuthID: profile.AuthID, Name: profile.Name})
	}
	return NewBackendSeries(ctx, BackendSeriesOptions{Credentials: credentials, BackupAPIKey: opts.BackupAPIKey, ModelMap: opts.ModelMap, SnapshotInterval: opts.SnapshotInterval})
}

// runNativeChild runs the native Claude with its prepared environment and returns its exit code.
func runNativeChild(ctx context.Context, bin string, args, env []string) (int, error) {
	lg().Info("native Claude starting")
	child := exec.CommandContext(ctx, bin, args...)
	child.Cancel = func() error { return child.Process.Signal(syscall.SIGTERM) }
	// This bounds process shutdown only; inference streams have no post-connect wall-clock timeout.
	child.WaitDelay = 5 * time.Second
	child.Env = env
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			code := exited.ExitCode()
			if code < 0 {
				code = 130
			}
			lg().Info("native Claude exited", "code", code)
			return code, nil
		}
		return 1, errors.New("native Claude could not start")
	}
	lg().Info("native Claude exited", "code", 0)
	return 0, nil
}

// Preflight checks native startup compatibility without opening profiles,
// acquiring credentials, starting a session, or modifying native settings.
func Preflight(ctx context.Context, args []string) (string, error) {
	environ, err := launchEnvironment(os.Environ(), "")
	if err != nil {
		return "", err
	}
	return preflight(ctx, args, environ)
}

func preflight(ctx context.Context, args, environ []string) (string, error) {
	if _, err := ChildEnvironment(environ, args, "https://127.0.0.1:1", "/unused", "", ""); err != nil {
		return "", err
	}
	if err := validateNativeSettings(ctx, environ); err != nil {
		return "", err
	}
	return resolveNativeBinary(ctx)
}

// ChildEnvironment preserves the master login while denying configuration that bypasses the
// process proxy or switches Claude to an API/third-party mode that disables native Remote Control.
// The proxy URL contains a private capability and must never be printed or placed in argv.
func ChildEnvironment(environ, args []string, proxyURL, caPath, clientCert, clientKey string) ([]string, error) {
	removed := map[string]bool{
		"HTTPS_PROXY": true, "https_proxy": true, "HTTP_PROXY": true, "http_proxy": true,
		"ALL_PROXY": true, "all_proxy": true, "NO_PROXY": true, "no_proxy": true,
		"NODE_EXTRA_CA_CERTS": true, "CLAUDE_CODE_CHILD_SESSION": true,
		"CLAUDE_CODE_CLIENT_CERT": true, "CLAUDE_CODE_CLIENT_KEY": true, "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE": true,
		"CLAUDE_CODE_SESSION_ID": true, "REMOTE_CLAW_SECRET_FILE": true,
		"VERCEL_AUTOMATION_BYPASS_SECRET": true,
		"DISABLE_AUTOUPDATER":             true,
	}
	for _, arg := range args {
		flag := strings.SplitN(arg, "=", 2)[0]
		switch flag {
		case "--settings", "--setting-sources", "--sdk-url", "--remote-control-session-id", "--claudeai-user-id", "--claudeai-org-id", "--api-key", "--base-url", "--cwd", "--worktree", "-w":
			return nil, errors.New("Claude launcher flags cannot override master identity or provider routing")
		}
	}
	out := make([]string, 0, len(environ)+3)
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if forbiddenProviderEnv(key) && strings.TrimSpace(value) != "" {
			return nil, errors.New("clear custom Claude provider, login-directory, or Node bypass settings before launching")
		}
		if removed[key] || forbiddenProviderEnv(key) {
			continue
		}
		// The selected inference login is held by the backend, never passed into the native master.
		if strings.HasPrefix(key, "CLAUDE_MASTER_") {
			continue
		}
		out = append(out, entry)
	}
	out = append(out, "HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL, "NODE_EXTRA_CA_CERTS="+caPath, "DISABLE_AUTOUPDATER=1")
	if clientCert != "" && clientKey != "" {
		// Claude offers this certificate to its HTTPS proxy, which is how the proxy knows its caller.
		out = append(out, "CLAUDE_CODE_CLIENT_CERT="+clientCert, "CLAUDE_CODE_CLIENT_KEY="+clientKey)
	}
	return out, nil
}
