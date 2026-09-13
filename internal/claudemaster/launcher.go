package claudemaster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// NativeClaudeVersion is the reviewed native endpoint/settings contract. Advancing it needs proof.
const NativeClaudeVersion = "2.1.269"

// Launch starts the native master with its existing personal Claude login and a process-only proxy.
// The caller must hold the profile lock until this returns. It never edits Claude configuration.
func Launch(ctx context.Context, profile Profile, model string, args []string) (int, error) {
	return LaunchWithDiagnostics(ctx, profile, model, args, nil)
}

// LaunchWithDiagnostics optionally emits numeric counters and fixed error-stage labels. It never
// emits proxy credentials, request content, URLs, or account identifiers.
func LaunchWithDiagnostics(ctx context.Context, profile Profile, model string, args []string, diagnostics io.Writer) (int, error) {
	return LaunchProfilesWithDiagnostics(ctx, []Profile{profile}, model, args, diagnostics)
}

// LaunchProfilesWithDiagnostics starts one native master with an ordered inference chain.
// The caller must hold every candidate profile lock until this returns. Only confirmed quota
// exhaustion can advance the chain; the native master identity and model never change.
func LaunchProfilesWithDiagnostics(ctx context.Context, profiles []Profile, model string, args []string, diagnostics io.Writer) (int, error) {
	if strings.TrimSpace(model) == "" {
		return 1, errors.New("an explicit backend model is required")
	}
	options, err := profileBackendOptions(profiles, model)
	if err != nil {
		return 1, err
	}
	args, err = NativeArguments(profiles[0].Provider, model, args)
	if err != nil {
		return 1, err
	}
	args, err = snapshotNativeHookSettings(args)
	if err != nil {
		return 1, err
	}
	bin, err := Preflight(ctx, args)
	if err != nil {
		return 1, err
	}
	certs, err := newProcessCertificate()
	if err != nil {
		return 1, err
	}
	defer func() { _ = os.RemoveAll(certs.dir) }()
	backend, err := NewFallbackBackend(ctx, options)
	if err != nil {
		return 1, errors.New("cannot start selected inference backends; check every profile and the shared model")
	}
	defer func() { _ = backend.Close() }()
	backend.SetOnFallback(func(fromIndex, toIndex int) {
		// Profile names are locally chosen, validated identifiers, never account IDs or tokens.
		fmt.Fprintf(os.Stderr, "\nclaude-master: inference quota exhausted for %s; using %s. Master login unchanged.\n", profiles[fromIndex].Name, profiles[toIndex].Name)
	})
	observation := &backendErrorObservation{}
	inference := backend.Handler()
	if diagnostics != nil {
		inference = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), backendErrorObservationKey{}, observation)
			backend.Handler().ServeHTTP(w, r.WithContext(ctx))
		})
	}
	proxy, err := StartProxy(ProxyOptions{Certificate: certs.leaf, Inference: inference})
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
	env, err := ChildEnvironment(os.Environ(), args, proxy.URL(), certs.caPath)
	if err != nil {
		return 1, err
	}
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
			return code, nil
		}
		return 1, errors.New("native Claude could not start")
	}
	return 0, nil
}

func profileBackendOptions(profiles []Profile, model string) ([]BackendOptions, error) {
	if len(profiles) == 0 {
		return nil, errors.New("at least one inference profile is required")
	}
	options := make([]BackendOptions, 0, len(profiles))
	names := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		if profile.Provider != profiles[0].Provider {
			return nil, errors.New("fallback profiles must use the same provider and model; mixed Claude/Codex fallback is not supported")
		}
		names = append(names, profile.Name)
		options = append(options, BackendOptions{AuthDir: profile.AuthDir, Provider: profile.Provider, AuthID: profile.AuthID, Model: model})
	}
	if err := ValidateProfileNames(names); err != nil {
		return nil, err
	}
	return options, nil
}

// Preflight checks native startup compatibility without opening profiles,
// acquiring credentials, starting a session, or modifying native settings.
func Preflight(ctx context.Context, args []string) (string, error) {
	if _, err := ChildEnvironment(os.Environ(), args, "http://127.0.0.1:1", "/unused"); err != nil {
		return "", err
	}
	if err := ValidateNativeSettings(ctx); err != nil {
		return "", err
	}
	return resolveNativeBinary(ctx)
}

// ChildEnvironment preserves the master login while denying configuration that bypasses the
// process proxy or switches Claude to an API/third-party mode that disables native Remote Control.
// The proxy URL contains a private capability and must never be printed or placed in argv.
func ChildEnvironment(environ, args []string, proxyURL, caPath string) ([]string, error) {
	removed := map[string]bool{
		"HTTPS_PROXY": true, "https_proxy": true, "HTTP_PROXY": true, "http_proxy": true,
		"ALL_PROXY": true, "all_proxy": true, "NO_PROXY": true, "no_proxy": true,
		"NODE_EXTRA_CA_CERTS": true, "CLAUDE_CODE_CHILD_SESSION": true,
		"CLAUDE_CODE_SESSION_ID": true, "REMOTE_CLAW_SECRET_FILE": true,
		"VERCEL_AUTOMATION_BYPASS_SECRET": true,
		"DISABLE_AUTOUPDATER": true,
	}
	settingsSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		flag := strings.SplitN(arg, "=", 2)[0]
		switch flag {
		case "--settings":
			if settingsSeen {
				return nil, errors.New("native hook settings may only be supplied once")
			}
			settingsSeen = true
			value := strings.TrimPrefix(arg, "--settings=")
			if arg == "--settings" {
				i++
				if i == len(args) {
					return nil, errors.New("native hook settings require a value")
				}
				value = args[i]
			}
			// Launch snapshots files first; this boundary never accepts a mutable filename.
			if _, err := nativeHookSettingsJSON([]byte(value)); err != nil {
				return nil, err
			}
		case "--setting-sources", "--sdk-url", "--remote-control-session-id", "--claudeai-user-id", "--claudeai-org-id", "--api-key", "--base-url", "--cwd", "--worktree", "-w":
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
	return out, nil
}

func verifyNativeVersion(ctx context.Context, bin string) error {
	cmd := exec.CommandContext(ctx, bin, "--version")
	var output boundedOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil || !supportedNativeVersion(output.String()) {
		return errors.New("native Claude version is unsupported; this launcher requires verified Claude Code " + NativeClaudeVersion)
	}
	return nil
}

func supportedNativeVersion(output string) bool {
	text := strings.TrimSpace(output)
	return text == NativeClaudeVersion || text == NativeClaudeVersion+" (Claude Code)"
}

type processCertificate struct {
	dir    string
	caPath string
	leaf   tls.Certificate
}

func newProcessCertificate() (*processCertificate, error) {
	dir, err := os.MkdirTemp("", "claude-master-certs-")
	if err != nil {
		return nil, errors.New("cannot create private process certificate directory")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dir)
		}
	}()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("cannot create process CA key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("cannot create certificate serial")
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "claude-master process CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, errors.New("cannot create process CA certificate")
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := writePrivateFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})); err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("cannot create process leaf key")
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("cannot create certificate serial")
	}
	leafTemplate := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "api.anthropic.com"}, DNSNames: []string{"api.anthropic.com"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(7 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, errors.New("cannot create process leaf certificate")
	}
	// Private CA and leaf keys remain only in this process. Only the scoped CA certificate is on disk.
	cleanup = false
	return &processCertificate{dir: dir, caPath: caPath, leaf: tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}, nil
}
