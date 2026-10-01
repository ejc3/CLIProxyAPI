package claudemaster

import (
	"bufio"
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
	Listen string // a specific private IP and port, e.g. 10.0.1.50:8443
	// OpenLoopback, when set, also serves a plain-HTTP listener with NO client certificate on this
	// loopback address (e.g. 127.0.0.1:8444), for clients that arrive through an authenticating
	// tunnel. Whatever can reach that address is trusted.
	OpenLoopback string
	StateDir     string    // the server's CA lives here (private, 0700)
	Out          io.Writer // one status line; never a secret
}

// Serve runs the proxy for other boxes until ctx ends. The caller holds every profile lock.
func Serve(ctx context.Context, profiles []Profile, opts ServeOptions) error {
	ip, _, err := privateEndpoint(opts.Listen)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	if opts.OpenLoopback != "" {
		if _, _, err := loopbackEndpoint(opts.OpenLoopback); err != nil {
			return fmt.Errorf("--open-loopback: %w", err)
		}
	}
	certs, err := loadOrCreatePersistentCertificate(opts.StateDir, serverNames(ip))
	if err != nil {
		return err
	}
	backend, err := newInferenceBackend(ctx, profiles, opts.LaunchOptions)
	if err != nil {
		return errors.New("cannot start the inference backend; check the profiles")
	}
	defer func() { _ = backend.Close() }()
	proxy, err := startServerProxy(certs, opts.Listen, opts.OpenLoopback, backend.Handler())
	if err != nil {
		return err
	}
	defer func() { _ = proxy.Close() }()
	if opts.Out != nil {
		fmt.Fprintf(opts.Out, "claude-master serving on %s; clients trust %s\n", proxy.Addr(), certs.caPath)
		if proxy.OpenAddr() != "" {
			fmt.Fprintf(opts.Out, "claude-master also serving WITHOUT client certificates on %s (loopback only): put an authenticating tunnel in front of it\n", proxy.OpenAddr())
		}
	}
	<-ctx.Done()
	return nil
}

// serverNames are the addresses the server's certificate vouches for: the one it listens on, and
// loopback, so a client can reach it through a local tunnel (an SSH or SSM port forward, a
// cloudflared access tunnel) by dialling 127.0.0.1 and still verify who it is talking to.
func serverNames(listen net.IP) []net.IP {
	loopback := net.IPv4(127, 0, 0, 1)
	if listen.Equal(loopback) {
		return []net.IP{loopback}
	}
	return []net.IP{listen, loopback}
}

func startServerProxy(certs *processCertificate, listen, openLoopback string, inference http.Handler) (*Proxy, error) {
	return StartProxy(ProxyOptions{
		GetCertificate: certs.getCertificate, Inference: inference,
		ProxyCertificate: certs.proxyServerCertificate, ClientCAs: certs.clientPool(), Listen: listen,
		OpenListen: openLoopback,
	})
}

// ConnectOptions points a box's Claude at a claude-master server.
type ConnectOptions struct {
	Server string // the server's private ADDRESS:PORT
	Dir    string // client.key, client.pem and ca.pem (see LoadClientIdentity)
	// Open instead reaches the server's open loopback listener (no client certificate) at this
	// loopback ADDRESS:PORT, typically the local end of an authenticating tunnel; CAFile is the
	// server's public ca.pem. Server and Dir are then unused.
	Open   string
	CAFile string
	Out    io.Writer
}

// Connect runs the native Claude through a claude-master server. It holds no profile and never falls
// back to this box's own login: a server that cannot be reached is an error.
func Connect(ctx context.Context, opts ConnectOptions, args []string) (int, error) {
	if opts.Open != "" {
		return connectOpen(ctx, opts, args)
	}
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
		return serverError(net.JoinHostPort(ip.String(), port), err)
	}
	defer func() { _ = conn.Close() }()
	// With TLS 1.3 the client handshake returns before the server has judged the client certificate:
	// a rejection arrives as an alert on the next read. Ask for one response so an unaccepted
	// certificate is reported here, not later as a confusing failure inside Claude. The proxy answers
	// anything that is not a CONNECT with a plain 400, which is all this needs.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := probeProxy(conn); err != nil {
		return serverError(net.JoinHostPort(ip.String(), port), err)
	}
	return nil
}

// probeProxy asks the connection for the proxy's own probe response and requires the header only a
// claude-master proxy sets, so "some HTTP service answered" is not mistaken for "the proxy answered".
func probeProxy(conn net.Conn) error {
	if _, err := io.WriteString(conn, "GET "+proxyProbePath+" HTTP/1.1\r\nHost: claude-master\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.Header.Get(proxyProbeHeader) != "1" {
		return errors.New("not a claude-master proxy")
	}
	return nil
}

func serverError(endpoint string, err error) error {
	reason := "is it running, and is this box allowed to reach it?"
	if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "bad") {
		reason = "it did not accept this box's certificate (expired, or issued by another server)"
	}
	return fmt.Errorf("cannot connect to the claude-master server at %s: %s", endpoint, reason)
}

func x509CertPool(pemData []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	return pool
}

// connectOpen runs the native Claude through the open loopback listener of a server, which asks for
// no certificate: the trust is the tunnel that leads to it. It only ever talks plain HTTP to a
// LOOPBACK address, so an unauthenticated proxy request never crosses a network.
func connectOpen(ctx context.Context, opts ConnectOptions, args []string) (int, error) {
	ip, port, err := loopbackEndpoint(opts.Open)
	if err != nil {
		return 2, fmt.Errorf("--open: %w", err)
	}
	if opts.CAFile == "" {
		return 2, errors.New("--open needs --ca FILE, the server's public ca.pem")
	}
	if pemData, err := os.ReadFile(opts.CAFile); err != nil || len(x509CertPool(pemData).Subjects()) == 0 { //nolint:staticcheck
		return 1, errors.New("cannot read a CA certificate from --ca")
	}
	endpoint := net.JoinHostPort(ip.String(), port)
	if err := checkOpen(ctx, endpoint); err != nil {
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
	env, err := ChildEnvironment(environ, args, "http://"+endpoint, opts.CAFile, "", "")
	if err != nil {
		return 1, err
	}
	return runNativeChild(ctx, bin, args, env)
}

// checkOpen asks the open listener for one response, so a tunnel that is down or leads nowhere is
// reported now and clearly instead of as a hang inside Claude.
func checkOpen(ctx context.Context, endpoint string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", endpoint)
	if err != nil {
		return fmt.Errorf("nothing is listening on %s: is the tunnel to the claude-master server running?", endpoint)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := probeProxy(conn); err != nil {
		return fmt.Errorf("%s is not a claude-master proxy: does the tunnel lead to the server's open listener?", endpoint)
	}
	return nil
}
