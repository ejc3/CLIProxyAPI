package claudemaster

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
)

// tokenCounts is one response's token usage as Anthropic reports it. Input excludes the cache
// fields, which the Messages API reports separately; output includes thinking.
type tokenCounts struct {
	input, output, cacheRead, cacheCreation int64
}

const (
	// usageLineLimit is the longest stream line kept for reading; usage events are far shorter, and a
	// longer line (a large content delta) is passed over without being held.
	usageLineLimit = 64 << 10
	// usageTailLimit is how much of the end of a JSON body is kept: its usage object comes last.
	usageTailLimit = 64 << 10
)

const (
	usageUndecided = iota
	usageSSE
	usageJSON
	usageOff
)

// usageScanner reads the usage Anthropic reports in a response from the bytes on their way to the
// client, without changing them: the native path forwards responses untouched and never parses
// them. In a stream it reads message_start's usage and then message_delta's, which is cumulative
// and so wins; in a JSON body, the top-level usage object.
type usageScanner struct {
	mode     int
	line     []byte
	skipping bool // inside a line longer than usageLineLimit
	tail     []byte
	size     int
	counts   tokenCounts
	seen     bool
}

// start picks how to read the body from the response's status and content type.
func (u *usageScanner) start(status int, contentType string) {
	switch {
	case status < 200 || status >= 300:
		u.mode = usageOff
	case strings.Contains(contentType, "event-stream"):
		u.mode = usageSSE
	case strings.Contains(contentType, "json"):
		u.mode = usageJSON
	default:
		u.mode = usageOff
	}
}

func (u *usageScanner) write(b []byte) {
	switch u.mode {
	case usageSSE:
		for len(b) > 0 {
			end := bytes.IndexByte(b, '\n')
			if end < 0 {
				u.keep(b)
				return
			}
			u.keep(b[:end])
			if !u.skipping {
				u.readLine(bytes.TrimRight(u.line, "\r"))
			}
			u.line, u.skipping = u.line[:0], false
			b = b[end+1:]
		}
	case usageJSON:
		u.size += len(b)
		u.tail = append(u.tail, b...)
		if len(u.tail) > usageTailLimit {
			u.tail = append(u.tail[:0], u.tail[len(u.tail)-usageTailLimit:]...)
		}
	}
}

// keep adds part of the current line, or stops keeping it once it is too long to be a usage event.
func (u *usageScanner) keep(part []byte) {
	if u.skipping {
		return
	}
	if len(u.line)+len(part) > usageLineLimit {
		u.line, u.skipping = u.line[:0], true
		return
	}
	u.line = append(u.line, part...)
}

func (u *usageScanner) readLine(line []byte) {
	payload, ok := bytes.CutPrefix(line, []byte("data:"))
	if !ok {
		return
	}
	switch gjson.GetBytes(payload, "type").String() {
	case "message_start":
		u.apply(gjson.GetBytes(payload, "message.usage"))
	case "message_delta":
		u.apply(gjson.GetBytes(payload, "usage"))
	}
}

// apply takes every count a usage object carries; a later object's counts replace earlier ones.
func (u *usageScanner) apply(usage gjson.Result) {
	if !usage.IsObject() {
		return
	}
	for _, field := range []struct {
		name string
		into *int64
	}{
		{"input_tokens", &u.counts.input},
		{"output_tokens", &u.counts.output},
		{"cache_read_input_tokens", &u.counts.cacheRead},
		{"cache_creation_input_tokens", &u.counts.cacheCreation},
	} {
		if value := usage.Get(field.name); value.Type == gjson.Number {
			*field.into = max(value.Int(), 0)
			u.seen = true
		}
	}
}

// result is the response's usage, once the body is complete.
func (u *usageScanner) result() (tokenCounts, bool) {
	if u.mode == usageJSON && len(u.tail) > 0 {
		if u.size <= usageTailLimit {
			u.apply(gjson.GetBytes(u.tail, "usage"))
		} else if at := bytes.LastIndex(u.tail, []byte(`"usage":`)); at >= 0 {
			// Only the end of a large body is kept; its usage object is the last one in it.
			u.apply(gjson.ParseBytes(u.tail[at+len(`"usage":`):]))
		}
		u.tail = nil
	}
	return u.counts, u.seen
}
