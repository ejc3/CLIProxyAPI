package claudemaster

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// meteredWriter notes when the first response byte (or the headers that announce it) leaves, so a
// request's time to first byte is measured where the client sees it.
type meteredWriter struct {
	gin.ResponseWriter
	firstWrite time.Time
}

func newMeteredWriter(w gin.ResponseWriter) *meteredWriter { return &meteredWriter{ResponseWriter: w} }

func (w *meteredWriter) mark() {
	if w.firstWrite.IsZero() {
		w.firstWrite = time.Now()
	}
}

func (w *meteredWriter) Write(b []byte) (int, error) { w.mark(); return w.ResponseWriter.Write(b) }
func (w *meteredWriter) WriteString(s string) (int, error) {
	w.mark()
	return w.ResponseWriter.WriteString(s)
}
func (w *meteredWriter) WriteHeaderNow() { w.mark(); w.ResponseWriter.WriteHeaderNow() }
func (w *meteredWriter) Flush()          { w.mark(); w.ResponseWriter.Flush() }

// finishRequest records one finished request (metrics and the debug line). It runs after the request's
// own cleanup, so the chosen account and its upstream headers are final.
func finishRequest(c *gin.Context, ctx context.Context, opts BackendOptions, w *meteredWriter, started time.Time, raw []byte, model string, isCount, isStream bool) {
	route := "inference"
	if isCount {
		route = "count_tokens"
	}
	obs := requestObservation{
		Route: route, Model: modelLabel(model), Client: clientFromContext(c.Request.Context()), Account: "unknown",
		Stream: isStream, Status: w.Status(), Duration: time.Since(started),
		ReqBytes: int64(len(raw)), RespBytes: int64(max(w.Size(), 0)),
		// The headers the client is about to see: Anthropic's own rate-limit headers are forwarded on the
		// response. (The executor keeps its own isolated copy, which is not readable from here.)
		RateLimits: w.Header().Clone(),
		Profile:    opts.Name,
	}
	if len(raw) > 0 {
		obs.Account = clientAccountKey(raw)
	}
	if !w.firstWrite.IsZero() {
		obs.TTFB = w.firstWrite.Sub(started)
	}
	if attempt := backendRequestAttempt(ctx); attempt != nil {
		attempt.mu.Lock()
		route, pickedAt := attempt.route, attempt.pickedAt
		attempt.mu.Unlock()
		if route != nil && route.selector != nil {
			obs.Profile = route.selector.profileName(route.authID)
		}
		if !pickedAt.IsZero() {
			obs.Overhead = pickedAt.Sub(started)
		}
	}
	observeRequest(obs)
}

// observeControl counts a request forwarded to the client's own account (Remote Control and the like). It is
// not timed or sized: it only has to show up in the total, with its client.
func observeControl(r *http.Request) {
	observeRequest(requestObservation{Route: "control", Client: clientFromContext(r.Context()), Account: "unknown"})
}
