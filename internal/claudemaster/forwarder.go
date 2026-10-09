package claudemaster

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// upstreamDialer opens a connection to the claude-master proxy (the in-process one, or a server's)
// on which the forwarder writes its own CONNECT.
type upstreamDialer func(ctx context.Context) (net.Conn, error)

// forwarderUser is the user name in the forwarder's proxy URL; only the password is checked.
const forwarderUser = "claude-master"

// localForwarder is the proxy Claude is given: plain HTTP on a loopback port of this box. A CONNECT
// to api.anthropic.com that carries this launch's token goes on to the claude-master proxy; every
// other CONNECT is dialled from this box and relayed blind. So the commands, hooks and servers Claude
// starts inherit a proxy that is transparent to them: they need no private CA and no client
// certificate, and their traffic leaves from this box, not from the server.
type localForwarder struct {
	listener net.Listener
	token    string
	upstream upstreamDialer
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	server   *http.Server
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// startLocalForwarder binds an ephemeral IPv4 loopback port. Whatever else on this box can reach the
// port can also tunnel through it, which grants nothing it could not do directly; only the token
// reaches the claude-master proxy.
func startLocalForwarder(upstream upstreamDialer) (*localForwarder, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, errors.New("cannot create the forwarder token")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("cannot bind the local forwarder")
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &localForwarder{
		listener: listener, token: hex.EncodeToString(secret), upstream: upstream,
		dial: (&net.Dialer{}).DialContext, ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{}),
	}
	f.server = &http.Server{
		Handler: http.HandlerFunc(f.handle), BaseContext: func(net.Listener) context.Context { return ctx },
		ErrorLog: log.New(io.Discard, "", 0),
	}
	f.wg.Add(1)
	go func() { defer f.wg.Done(); _ = f.server.Serve(listener) }()
	return f, nil
}

// URL carries the token, a private capability: it goes into Claude's environment only, never into
// argv or a log.
func (f *localForwarder) URL() string {
	return "http://" + forwarderUser + ":" + f.token + "@" + f.listener.Addr().String()
}

// Close stops the listener and ends every tunnel.
func (f *localForwarder) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	for conn := range f.conns {
		_ = conn.Close()
	}
	f.mu.Unlock()
	f.cancel()
	err := f.server.Close()
	f.wg.Wait()
	return err
}

// begin registers a running tunnel Close waits for; it returns false once the forwarder is closed.
func (f *localForwarder) begin() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.wg.Add(1)
	return true
}

// track registers a connection Close must end; it returns false once the forwarder is closed.
func (f *localForwarder) track(conn net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[conn] = struct{}{}
	return true
}

func (f *localForwarder) untrack(conn net.Conn) {
	f.mu.Lock()
	delete(f.conns, conn)
	f.mu.Unlock()
	_ = conn.Close()
}

func (f *localForwarder) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "this proxy only tunnels CONNECT", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(r.RequestURI)
	if n, errPort := strconv.Atoi(port); err != nil || host == "" || errPort != nil || n < 1 || n > 65535 {
		http.Error(w, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	toMaster := port == "443" && strings.TrimRight(strings.ToLower(host), ".") == masterAPIHost && f.authorized(r)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	if !f.begin() {
		return
	}
	defer f.wg.Done()
	raw, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if !f.track(raw) {
		_ = raw.Close()
		return
	}
	defer f.untrack(raw)
	remote, tracked, err := f.open(toMaster, net.JoinHostPort(host, port))
	if err != nil {
		lg().Debug("forwarder tunnel failed", "to_master", toMaster)
		_, _ = buffered.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		_ = buffered.Flush()
		return
	}
	defer f.untrack(tracked)
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	// Bytes the client pipelined after its CONNECT are already in the reader.
	relay(&proxyBufferedConn{Conn: raw, reader: buffered.Reader}, remote)
}

// authorized checks the token in Proxy-Authorization (Basic, password only).
func (f *localForwarder) authorized(r *http.Request) bool {
	scheme, encoded, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return false
	}
	_, password, ok := strings.Cut(string(decoded), ":")
	return ok && subtle.ConstantTimeCompare([]byte(password), []byte(f.token)) == 1
}

// open dials the tunnel's far end, tracked so Close ends it even mid-handshake: the claude-master
// proxy for api.anthropic.com, or the address itself. It returns the tunnel and the tracked
// connection beneath it, which the caller untracks.
func (f *localForwarder) open(toMaster bool, address string) (net.Conn, net.Conn, error) {
	var conn net.Conn
	var err error
	if toMaster {
		conn, err = f.upstream(f.ctx)
	} else {
		conn, err = f.dial(f.ctx, "tcp", address)
	}
	if err != nil {
		return nil, nil, err
	}
	if !f.track(conn) {
		_ = conn.Close()
		return nil, nil, errors.New("forwarder closed")
	}
	if !toMaster {
		return conn, conn, nil
	}
	tunnel, err := connectMaster(conn)
	if err != nil {
		f.untrack(conn)
		return nil, nil, err
	}
	return tunnel, conn, nil
}

// connectMaster asks the claude-master proxy on conn for a tunnel to api.anthropic.com.
func connectMaster(conn net.Conn) (net.Conn, error) {
	authority := masterAPIHost + ":443"
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claude-master proxy answered CONNECT with %d", resp.StatusCode)
	}
	return &proxyBufferedConn{Conn: conn, reader: reader}, nil
}

// relay copies both ways until either side ends, then closes both.
func relay(a, b net.Conn) {
	finished := make(chan struct{})
	go func() {
		_, _ = io.Copy(b, a)
		_ = a.Close()
		_ = b.Close()
		close(finished)
	}()
	_, _ = io.Copy(a, b)
	_ = a.Close()
	_ = b.Close()
	<-finished
}
