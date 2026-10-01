package claudemaster

import (
	"context"
	"crypto/tls"
	"net"
	"regexp"
	"strings"
	"time"
)

// Which client is on the other end of a tunnel. The certificate listener knows its client by the name in
// its certificate (the name `claude-master issue` signed); the open loopback listener only knows it came
// through a tunnel. The name travels with the inner connection into every request on it.

type clientCtxKey struct{}

// clientFromContext is the connecting client's name for a request: a certificate name, "tunnel" for the
// open listener, "local" for a launch's own Claude, or "unknown".
func clientFromContext(ctx context.Context) string {
	if ctx == nil {
		return "unknown"
	}
	if name, ok := ctx.Value(clientCtxKey{}).(string); ok && name != "" {
		return name
	}
	return "unknown"
}

// identifyClient names whoever is on the far end of a hijacked outer connection and says which listener
// it came in on.
func identifyClient(raw net.Conn) (name, listener string) {
	if tc, ok := raw.(*tls.Conn); ok {
		state := tc.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			if cn := strings.TrimSpace(state.PeerCertificates[0].Subject.CommonName); cn != "" {
				return cn, "cert"
			}
		}
		return "unknown", "cert"
	}
	return "tunnel", "open"
}

// handshakeErrorWriter turns the http.Server's TLS-handshake complaints into one warning a minute per
// remote address: a scanner or a box with an expired certificate is visible without flooding the log.
type handshakeErrorWriter struct {
	limiter *every
	onError func()
}

var handshakeLine = regexp.MustCompile(`TLS handshake error from ([^:\s]+)(?::\d+)?: (.*)`)

func (w *handshakeErrorWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if m := handshakeLine.FindStringSubmatch(line); m != nil {
		if w.onError != nil {
			w.onError()
		}
		if w.limiter.allow("handshake:" + m[1]) {
			lg().Warn("client TLS handshake failed", "remote", m[1], "reason", m[2])
		}
		return len(p), nil
	}
	lg().Debug("proxy server notice", "text", line)
	return len(p), nil
}

func newHandshakeErrorWriter(onError func()) *handshakeErrorWriter {
	return &handshakeErrorWriter{limiter: newEvery(time.Minute), onError: onError}
}
