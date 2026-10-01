package claudemaster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ServeOptions configures a shared claude-master server: one box that holds the subscription logins
// and routes inference for every client box that presents a certificate it issued.
type ServeOptions struct {
	LaunchOptions
	Listen   string    // a specific private IP and port, e.g. 10.0.1.50:8443
	StateDir string    // the server's CA lives here (private, 0700)
	Out      io.Writer // one status line; never a secret
}

// Serve runs the proxy for other boxes until ctx ends. The caller holds every profile lock.
func Serve(ctx context.Context, profiles []Profile, opts ServeOptions) error {
	ip, _, err := privateEndpoint(opts.Listen)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	certs, err := loadOrCreatePersistentCertificate(opts.StateDir, []net.IP{ip})
	if err != nil {
		return err
	}
	backend, err := newInferenceBackend(ctx, profiles, opts.LaunchOptions)
	if err != nil {
		return errors.New("cannot start the inference backend; check the profiles")
	}
	defer func() { _ = backend.Close() }()
	proxy, err := startServerProxy(certs, opts.Listen, backend.Handler())
	if err != nil {
		return err
	}
	defer func() { _ = proxy.Close() }()
	if opts.Out != nil {
		fmt.Fprintf(opts.Out, "claude-master serving on %s; clients trust %s\n", proxy.Addr(), certs.caPath)
	}
	<-ctx.Done()
	return nil
}

func startServerProxy(certs *processCertificate, listen string, inference http.Handler) (*Proxy, error) {
	return StartProxy(ProxyOptions{
		GetCertificate: certs.getCertificate, Inference: inference,
		ProxyCertificate: certs.proxyServerCertificate, ClientCAs: certs.clientPool(), Listen: listen,
	})
}

// ConnectOptions points a box's Claude at a claude-master server.
type ConnectOptions struct {
	Server string // the server's private ADDRESS:PORT
	Dir    string // client.key, client.pem and ca.pem (see LoadClientIdentity)
	Out    io.Writer
}

// Connect runs the native Claude through a claude-master server. It holds no profile and never falls
// back to this box's own login: a server that cannot be reached is an error.
func Connect(ctx context.Context, opts ConnectOptions, args []string) (int, error) {
	ip, port, err := privateEndpoint(opts.Server)
	if err != nil {
		return 2, fmt.Errorf("--server: %w", err)
	}
	identity, err := LoadClientIdentity(opts.Dir)
	if err != nil {
		return 1, err
	}
	if left := time.Until(identity.Expires); left < 3*24*time.Hour && opts.Out != nil {
		fmt.Fprintf(opts.Out, "claude-master: this box's certificate expires %s; ask the server for a new one\n", identity.Expires.Format("2006-01-02"))
	}
	if err := checkServer(ctx, ip, port, identity); err != nil {
		return 1, err
	}
	environ, err := launchEnvironment(os.Environ(), "")
	if err != nil {
		return 1, err
	}
	args, err = NativeArguments("claude", args)
	if err != nil {
		return 1, err
	}
	bin, err := preflight(ctx, args, environ)
	if err != nil {
		return 1, err
	}
	env, err := ChildEnvironment(environ, args, "https://"+net.JoinHostPort(ip.String(), port), identity.CAPath, identity.CertPath, identity.KeyPath)
	if err != nil {
		return 1, err
	}
	return runNativeChild(ctx, bin, args, env)
}

// checkServer completes one TLS handshake with this box's client certificate, so a wrong address, a
// certificate the server does not accept, or a server that is down is reported now and clearly.
func checkServer(ctx context.Context, ip net.IP, port string, identity ClientIdentity) error {
	pair, err := tls.LoadX509KeyPair(identity.CertPath, identity.KeyPath)
	if err != nil {
		return errors.New("cannot load this box's client certificate")
	}
	caPEM, err := os.ReadFile(identity.CAPath)
	if err != nil {
		return errors.New("cannot read ca.pem")
	}
	roots := x509CertPool(caPEM)
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: ip.String(), MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		reason := "is it running, and is this box allowed to reach it?"
		if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "bad") {
			reason = "it did not accept this box's certificate (expired, or issued by another server)"
		}
		return fmt.Errorf("cannot connect to the claude-master server at %s: %s", net.JoinHostPort(ip.String(), port), reason)
	}
	_ = conn.Close()
	return nil
}

func x509CertPool(pemData []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	return pool
}
