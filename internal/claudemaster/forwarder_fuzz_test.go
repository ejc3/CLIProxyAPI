package claudemaster

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// forwarderPairListener hands the forwarder in-memory Unix socket pairs instead of TCP
// connections, so fuzzing uses no ports (a TCP connection per input exhausts the ephemeral range)
// while a client can still half-close its side.
type forwarderPairListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newForwarderPairListener() *forwarderPairListener {
	return &forwarderPairListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *forwarderPairListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *forwarderPairListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *forwarderPairListener) Addr() net.Addr { return &net.UnixAddr{Name: "pair", Net: "unix"} }

// dial returns the client end of a new pair whose server end the forwarder accepts.
func (l *forwarderPairListener) dial(t *testing.T) *net.UnixConn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	ends := make([]net.Conn, 2)
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "forwarder-pair")
		ends[i], err = net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case l.conns <- ends[1]:
	case <-l.done:
		t.Fatal("the pair listener is closed")
	}
	return ends[0].(*net.UnixConn)
}

// forwarderOracleRoutesToMaster is an independent statement of the routing rule: only a CONNECT to
// api.anthropic.com:443 whose first Proxy-Authorization is Basic with exactly the token reaches the
// claude-master proxy.
func forwarderOracleRoutesToMaster(r *http.Request, token string) bool {
	if r.Method != http.MethodConnect {
		return false
	}
	host, port, err := net.SplitHostPort(r.RequestURI)
	if err != nil || port != "443" || strings.TrimRight(strings.ToLower(host), ".") != masterAPIHost {
		return false
	}
	value := r.Header.Get("Proxy-Authorization")
	if len(value) < 6 || !strings.EqualFold(value[:6], "basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
	if err != nil {
		return false
	}
	_, password, ok := strings.Cut(string(decoded), ":")
	return ok && password == token
}

// FuzzForwarderRequest sends arbitrary bytes to a live forwarder. "TOKENB64" in the input stands for
// the forwarder's real credential and "TOKEN" for its token, so the fuzzer can reach the authorized
// path. Whatever arrives, the
// forwarder must not reach the claude-master proxy unless the oracle says the request may, must
// answer with HTTP or nothing, and must shut down cleanly. Plain `go test` runs only the seeds.
func FuzzForwarderRequest(f *testing.F) {
	// TOKENB64 stands for base64("claude-master:<token>"), the credential as Claude sends it.
	auth := func(password string) string {
		if password == "TOKEN" {
			return "Proxy-Authorization: Basic TOKENB64\r\n"
		}
		return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(forwarderUser+":"+password)) + "\r\n"
	}
	for _, seed := range []string{
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n" + auth("TOKEN") + "\r\n",
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n",
		"CONNECT API.ANTHROPIC.COM.:443 HTTP/1.1\r\nHost: x\r\n" + auth("TOKEN") + "\r\nclient-hello",
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\n" + auth("TOKENx") + "\r\n",
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\n" + auth("wrong") + auth("TOKEN") + "\r\n",
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Bearer TOKEN\r\n\r\n",
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\nProxy-Authorization: basic !!!\r\n\r\n",
		"CONNECT api.anthropic.com:8443 HTTP/1.1\r\nHost: x\r\n" + auth("TOKEN") + "\r\n",
		"CONNECT api.anthropic.com.evil:443 HTTP/1.1\r\nHost: x\r\n" + auth("TOKEN") + "\r\n",
		"CONNECT [::1]:443 HTTP/1.1\r\nHost: x\r\n\r\n",
		"CONNECT example.com:0 HTTP/1.1\r\nHost: x\r\n\r\n",
		"CONNECT example.com HTTP/1.1\r\nHost: x\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.0\r\n\r\n",
		"GET http://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n" + auth("TOKEN") + "\r\n",
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\n" + auth("TOKEN") + "\r\n",
		"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
		"CONNECT a:1 HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("y", 8192) + "\r\n\r\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var masterDials, directDials atomic.Int32
		pairs := newForwarderPairListener()
		fw, err := serveLocalForwarder(pairs, func(context.Context) (net.Conn, error) {
			masterDials.Add(1)
			return nil, errors.New("the fuzz master refuses")
		})
		if err != nil {
			t.Fatal(err)
		}
		fw.dial = func(context.Context, string, string) (net.Conn, error) {
			directDials.Add(1)
			return nil, errors.New("the fuzz internet refuses")
		}
		credential := base64.StdEncoding.EncodeToString([]byte(forwarderUser + ":" + fw.token))
		data = bytes.ReplaceAll(data, []byte("TOKENB64"), []byte(credential))
		data = bytes.ReplaceAll(data, []byte("TOKEN"), []byte(fw.token))

		conn := pairs.dial(t)
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // a stuck exchange fails, it does not hang
		_, _ = conn.Write(data)
		_ = conn.CloseWrite()
		response, _ := io.ReadAll(conn)
		_ = conn.Close()
		closed := make(chan error, 1)
		go func() { closed <- fw.Close() }()
		select {
		case <-closed:
		case <-time.After(10 * time.Second):
			t.Fatalf("Close hung after input %q", data)
		}

		if len(response) > 0 && !bytes.HasPrefix(response, []byte("HTTP/1.")) {
			t.Fatalf("answered %q to %q", response, data)
		}
		allowed := false
		if r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data))); err == nil {
			allowed = forwarderOracleRoutesToMaster(r, fw.token)
		}
		if masterDials.Load() > 0 && !allowed {
			t.Fatalf("reached the claude-master proxy for %q", data)
		}
		if directDials.Load() > 0 && allowed {
			t.Fatalf("sent an authorized request for %q past the claude-master proxy", data)
		}
		if masterDials.Load()+directDials.Load() > 1 {
			t.Fatalf("one request dialled %d times", masterDials.Load()+directDials.Load())
		}
		fw.mu.Lock()
		defer fw.mu.Unlock()
		if len(fw.conns) != 0 {
			t.Fatalf("%d connections tracked after Close", len(fw.conns))
		}
	})
}

// forwarderChaosEnd is a far end that announces itself with a one-byte banner, then echoes; as the
// master it first answers the CONNECT, or refuses it.
type forwarderChaosEnd struct {
	listener net.Listener
	banner   byte
	refuse   atomic.Bool
	stall    atomic.Bool   // the next CONNECT is read and never answered
	stalled  chan struct{} // receives once per stalled CONNECT
}

func startForwarderChaosEnd(t *testing.T, banner byte, master bool) *forwarderChaosEnd {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &forwarderChaosEnd{listener: listener, banner: banner, stalled: make(chan struct{}, 64)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				reader := bufio.NewReader(conn)
				if master {
					if _, err := http.ReadRequest(reader); err != nil {
						return
					}
					if e.stall.CompareAndSwap(true, false) {
						e.stalled <- struct{}{}
						_, _ = io.Copy(io.Discard, reader) // until the forwarder hangs up
						return
					}
					if e.refuse.Load() {
						_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
						return
					}
					if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
						return
					}
				}
				if _, err := conn.Write([]byte{e.banner}); err != nil {
					return
				}
				_, _ = io.Copy(conn, reader)
			}()
		}
	}()
	return e
}

// TestForwarderSeededChaos drives a forwarder through a reproducible random mix of tunnels, garbage,
// abandoned and half-finished clients, dead far ends, refusing masters and concurrent bursts, then
// closes it mid-traffic. Every tunnel must reach the far end its request names; nothing may be left
// tracked. A failure names the seed and step, which replays it exactly.
func TestForwarderSeededChaos(t *testing.T) {
	for seed := uint64(1); seed <= 12; seed++ {
		t.Run(fmt.Sprint("seed-", seed), func(t *testing.T) { forwarderChaos(t, seed, 48) })
	}
}

func forwarderChaos(t *testing.T, seed uint64, steps int) {
	rng := rand.New(rand.NewPCG(seed, 0x6f72776172646572))
	master := startForwarderChaosEnd(t, 'M', true)
	direct := startForwarderChaosEnd(t, 'D', false)
	public := startForwarderChaosEnd(t, 'P', false)

	fw, err := startLocalForwarder(plainUpstream(master.listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	fw.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "dead.example:443" {
			// Refused outright: a closed port of our own could be handed to another listener.
			return nil, syscall.ECONNREFUSED
		}
		target := map[string]string{
			"direct.example:443":    direct.listener.Addr().String(),
			"api.anthropic.com:443": public.listener.Addr().String(),
		}[address]
		if target == "" {
			return nil, fmt.Errorf("no chaos host %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	authHeader := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(forwarderUser+":"+fw.token)) + "\r\n"

	type tunnel struct {
		conn   net.Conn
		reader *bufio.Reader
	}
	where := func(step int, what string) string { return fmt.Sprintf("seed %d step %d (%s)", seed, step, what) }
	// open writes a CONNECT and returns the status, and the tunnel after reading the far end's banner.
	open := func(step int, authority string, withToken bool, pipelined []byte) (int, *tunnel) {
		conn, err := net.Dial("tcp", fw.listener.Addr().String())
		if err != nil {
			t.Fatalf("%s: dial: %v", where(step, authority), err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		header := ""
		if withToken {
			header = authHeader
		}
		request := append([]byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", authority, authority, header)), pipelined...)
		if _, err := conn.Write(request); err != nil {
			t.Fatalf("%s: write: %v", where(step, authority), err)
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("%s: response: %v", where(step, authority), err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return resp.StatusCode, nil
		}
		return resp.StatusCode, &tunnel{conn: conn, reader: reader}
	}
	expectBanner := func(step int, what string, tun *tunnel, want byte) {
		got, err := tun.reader.ReadByte()
		if err != nil || got != want {
			t.Fatalf("%s: banner %q, %v; want %q", where(step, what), got, err, want)
		}
	}
	echo := func(step int, what string, tun *tunnel, size int) {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(rng.IntN(256))
		}
		errs := make(chan error, 1)
		go func() { _, err := tun.conn.Write(payload); errs <- err }()
		got := make([]byte, size)
		if _, err := io.ReadFull(tun.reader, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("%s: echo of %d bytes failed: %v", where(step, what), size, err)
		}
		if err := <-errs; err != nil {
			t.Fatalf("%s: write: %v", where(step, what), err)
		}
	}
	// A tunnel of one of the routable kinds: authority, token, and the banner it must reach.
	kinds := []struct {
		authority string
		token     bool
		banner    byte
	}{
		{"direct.example:443", false, 'D'},
		{"direct.example:443", true, 'D'},
		{"api.anthropic.com:443", true, 'M'},
		{"API.Anthropic.COM.:443", true, 'M'},
		{"api.anthropic.com:443", false, 'P'},
	}

	var held []*tunnel // live tunnels Close must end
	for step := 0; step < steps; step++ {
		switch op := rng.IntN(10); op {
		case 0, 1, 2: // a routable tunnel, used and kept or closed
			k := kinds[rng.IntN(len(kinds))]
			pipelined := []byte(nil)
			if rng.IntN(3) == 0 {
				pipelined = []byte("early")
			}
			status, tun := open(step, k.authority, k.token, pipelined)
			if status != http.StatusOK {
				t.Fatalf("%s: status %d", where(step, k.authority), status)
			}
			expectBanner(step, k.authority, tun, k.banner)
			if pipelined != nil {
				got := make([]byte, len(pipelined))
				if _, err := io.ReadFull(tun.reader, got); err != nil || !bytes.Equal(got, pipelined) {
					t.Fatalf("%s: pipelined bytes came back as %q, %v", where(step, k.authority), got, err)
				}
			}
			echo(step, k.authority, tun, rng.IntN(64<<10)+1)
			if rng.IntN(2) == 0 {
				held = append(held, tun)
			} else {
				_ = tun.conn.Close()
			}
		case 3: // garbage instead of a request
			conn, err := net.Dial("tcp", fw.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			junk := make([]byte, rng.IntN(512)+1)
			for i := range junk {
				junk[i] = byte(rng.IntN(256))
			}
			_, _ = conn.Write(append(junk, "\r\n\r\n"...))
			response, _ := io.ReadAll(io.LimitReader(conn, 4096))
			if len(response) > 0 && !bytes.HasPrefix(response, []byte("HTTP/1.")) {
				t.Fatalf("%s: answered %q", where(step, "garbage"), response)
			}
			_ = conn.Close()
		case 4: // a client that leaves before hearing back
			conn, err := net.Dial("tcp", fw.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_, _ = fmt.Fprintf(conn, "CONNECT direct.example:443 HTTP/1.1\r\nHost: direct.example:443\r\n\r\n")
			_ = conn.Close()
		case 5: // a client that writes half a message and leaves
			k := kinds[rng.IntN(len(kinds))]
			_, tun := open(step, k.authority, k.token, nil)
			expectBanner(step, k.authority, tun, k.banner)
			_, _ = tun.conn.Write(make([]byte, rng.IntN(4096)+1))
			_ = tun.conn.Close()
		case 6: // a far end that is down
			if status, _ := open(step, "dead.example:443", false, nil); status != http.StatusBadGateway {
				t.Fatalf("%s: status %d, want 502", where(step, "dead"), status)
			}
		case 7: // a master that refuses
			master.refuse.Store(true)
			status, _ := open(step, "api.anthropic.com:443", true, nil)
			master.refuse.Store(false)
			if status != http.StatusBadGateway {
				t.Fatalf("%s: status %d, want 502", where(step, "refused"), status)
			}
		case 9: // a tunnel left waiting on a master that never answers, until Close
			master.stall.Store(true)
			conn, err := net.Dial("tcp", fw.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := fmt.Fprintf(conn, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n%s\r\n", authHeader); err != nil {
				t.Fatal(err)
			}
			select {
			case <-master.stalled:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the master never saw the stalled CONNECT", where(step, "stall"))
			}
			held = append(held, &tunnel{conn: conn, reader: bufio.NewReader(conn)})
		case 8: // a concurrent burst of routable tunnels
			n := rng.IntN(6) + 2
			picks := make([]int, n)
			sizes := make([]int, n)
			payloads := make([][]byte, n)
			for i := range picks {
				picks[i], sizes[i] = rng.IntN(len(kinds)), rng.IntN(16<<10)+1
				payloads[i] = make([]byte, sizes[i])
				for j := range payloads[i] {
					payloads[i][j] = byte(rng.IntN(256))
				}
			}
			var wg sync.WaitGroup
			failures := make(chan string, n)
			for i := range picks {
				wg.Add(1)
				go func() {
					defer wg.Done()
					k := kinds[picks[i]]
					conn, err := net.Dial("tcp", fw.listener.Addr().String())
					if err != nil {
						failures <- err.Error()
						return
					}
					defer func() { _ = conn.Close() }()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					header := ""
					if k.token {
						header = authHeader
					}
					if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", k.authority, k.authority, header); err != nil {
						failures <- err.Error()
						return
					}
					reader := bufio.NewReader(conn)
					resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
					if err != nil || resp.StatusCode != http.StatusOK {
						failures <- fmt.Sprintf("burst %d: %v", i, err)
						return
					}
					if banner, err := reader.ReadByte(); err != nil || banner != k.banner {
						failures <- fmt.Sprintf("burst %d reached %q, want %q", i, banner, k.banner)
						return
					}
					go func() { _, _ = conn.Write(payloads[i]) }()
					got := make([]byte, sizes[i])
					if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, payloads[i]) {
						failures <- fmt.Sprintf("burst %d echo: %v", i, err)
					}
				}()
			}
			wg.Wait()
			close(failures)
			for failure := range failures {
				t.Fatalf("%s: %s", where(step, "burst"), failure)
			}
		}
	}

	// Close mid-traffic: every held tunnel ends, nothing stays tracked, nothing accepts.
	closed := make(chan error, 1)
	go func() { closed <- fw.Close() }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatalf("seed %d: Close hung with %d tunnels held", seed, len(held))
	}
	for i, tun := range held {
		_ = tun.conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.Copy(io.Discard, tun.reader); err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "reset") {
			t.Errorf("seed %d: held tunnel %d did not end: %v", seed, i, err)
		}
		_ = tun.conn.Close()
	}
	fw.mu.Lock()
	tracked := len(fw.conns)
	fw.mu.Unlock()
	if tracked != 0 {
		t.Fatalf("seed %d: %d connections tracked after Close", seed, tracked)
	}
	if conn, err := net.Dial("tcp", fw.listener.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatalf("seed %d: the forwarder accepts after Close", seed)
	}
}
