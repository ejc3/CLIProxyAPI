package clawmaster

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// A profile reserve is the owner's opt-in exception to "the poll is advisory": a reserve of N on a
// subscription profile holds the last N% of its weekly allowance out of the pool. The pool treats the
// profile as out once the polled weekly usage reaches (100 - N)% (always, for N = 100, whatever the poll
// says), exactly as it treats a subscription Anthropic rejected with a credential-scoped 429 (see
// backendSeriesSelector.reservedLocked). N = 0 or no entry is the ordinary behaviour. Only the weekly
// window counts, and the API-key backup is never reserved.

// profileReserveRetryAfter is the retry-after the pool gives for a reserved subscription that has no
// weekly reset to wait for: one held at 100 (only a change to the reserve file lifts it), or one whose
// reset is not known.
const profileReserveRetryAfter = time.Hour

var profileReserves atomic.Pointer[map[string]int]

// SetProfileReserves swaps in the reserves the pool uses (profile name -> percent held back, 0..100) and
// reports whether they changed.
func SetProfileReserves(reserves map[string]int) bool {
	next := maps.Clone(reserves)
	if next == nil {
		next = map[string]int{}
	}
	previous := profileReserves.Swap(&next)
	if previous == nil {
		return len(next) > 0
	}
	return !maps.Equal(*previous, next)
}

// profileReserveFor is the reserve configured for a profile name, 0 when none.
func profileReserveFor(name string) int {
	if current := profileReserves.Load(); current != nil {
		return (*current)[name]
	}
	return 0
}

var profileReservePercent = regexp.MustCompile(`^[0-9]{1,3}$`)

// ParseProfileReserves reads PROFILE=N lines: N an integer from 0 to 100, a line starting with # a
// comment, blank lines ignored. Any other line, a percent outside 0..100 or a profile named twice makes
// the whole file invalid. The error names the line number and what is wrong, never the line's text.
func ParseProfileReserves(data []byte) (map[string]int, error) {
	reserves := make(map[string]int)
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || ValidateProfileName(name) != nil {
			return nil, fmt.Errorf("line %d: a profile reserve must be PROFILE=N", i+1)
		}
		if !profileReservePercent.MatchString(value) {
			return nil, fmt.Errorf("line %d: the reserve of %s must be a whole percent from 0 to 100", i+1, name)
		}
		percent, err := strconv.Atoi(value)
		if err != nil || percent > 100 {
			return nil, fmt.Errorf("line %d: the reserve of %s must be a whole percent from 0 to 100", i+1, name)
		}
		if _, seen := reserves[name]; seen {
			return nil, fmt.Errorf("line %d: %s is named twice", i+1, name)
		}
		reserves[name] = percent
	}
	return reserves, nil
}

// LoadProfileReserves reads and parses a --profile-reserve-file.
func LoadProfileReserves(file string) (map[string]int, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.New("cannot read --profile-reserve-file")
	}
	return ParseProfileReserves(data)
}

// describeProfileReserves is the reserves as "profile=N" pairs in name order, for the log.
func describeProfileReserves(reserves map[string]int) string {
	pairs := make([]string, 0, len(reserves))
	for name, percent := range reserves {
		pairs = append(pairs, fmt.Sprintf("%s=%d", name, percent))
	}
	sort.Strings(pairs)
	if len(pairs) == 0 {
		return "none"
	}
	return strings.Join(pairs, " ")
}

// StartProfileReserves loads the reserve file once and then watches it (WatchProfileReserves) until ctx
// ends. A file that is missing or does not parse holds no profile back and is logged; the server starts
// regardless.
func StartProfileReserves(ctx context.Context, file string, every time.Duration) {
	start := accountLabelsFingerprint(file) // before the read: a change made right after it is still seen
	if reserves, err := LoadProfileReserves(file); err != nil {
		lg().Warn("profile reserve file was not loaded; no profile is held in reserve until it loads", "why", err.Error())
	} else {
		SetProfileReserves(reserves)
		lg().Info("profile reserves loaded", "reserves", describeProfileReserves(reserves))
	}
	go watchProfileReservesFrom(ctx, file, start, every)
}

// WatchProfileReserves re-reads the reserve file when it changes (a new inode, size or modification time:
// replace it with a rename) and swaps the reserves in, so a change reaches routing without a restart. A
// file that does not load keeps the reserves in use, and the failure is logged once for that version of the
// file. It returns when ctx ends.
func WatchProfileReserves(ctx context.Context, file string, every time.Duration) {
	watchProfileReservesFrom(ctx, file, accountLabelsFingerprint(file), every)
}

func watchProfileReservesFrom(ctx context.Context, file, last string, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := accountLabelsFingerprint(file)
		if now == last || now == "" {
			continue
		}
		last = now
		reserves, err := LoadProfileReserves(file)
		if err != nil {
			lg().Warn("profile reserve file changed but was not loaded; the previous reserves stay", "why", err.Error())
			continue
		}
		if SetProfileReserves(reserves) {
			lg().Info("profile reserves loaded", "reserves", describeProfileReserves(reserves))
		}
	}
}

// ---------------------------------------------------------------- selection

// profileReserveLocked is the reserve configured for a subscription (0 for the API-key backup, which is
// never reserved, and for a profile with no name).
func (s *backendSeriesSelector) profileReserveLocked(authID string) int {
	if authID == "" || authID == s.backupAuthID {
		return 0
	}
	name := s.names[authID]
	if name == "" {
		return 0
	}
	if s.reserveFor != nil {
		return s.reserveFor(name)
	}
	return profileReserveFor(name)
}

// reservedLocked reports whether the subscription's reserve takes it out of the pool now: always at a
// reserve of 100, else once the weekly usage the poll and response headers report reaches (100 - N)% of
// the allowance. An unknown weekly figure leaves it in (the poll stays advisory otherwise), and the week's
// reset (currentQuotaLocked starts a new week at 0) brings it back. A change is logged once.
func (s *backendSeriesSelector) reservedLocked(authID string) bool {
	percent := s.profileReserveLocked(authID)
	q := s.currentQuotaLocked(authID)
	out := percent >= 100 || percent > 0 && q.known && q.used >= float64(100-percent)/100
	s.noteReserveLocked(authID, out, percent, q)
	return out
}

// heldLocked: the subscription is out of the pool, by Anthropic's rejection of a real request (a
// credential-scoped 429 still in force) or by its reserve.
func (s *backendSeriesSelector) heldLocked(authID string) bool {
	blocked := s.quotaBlockedLocked(authID)
	return s.reservedLocked(authID) || blocked
}

// reservedNoteLocked completes an all-out refusal's reason when a reserve holds any subscription out.
func (s *backendSeriesSelector) reservedNoteLocked() string {
	for _, authID := range s.authIDs {
		if s.reservedLocked(authID) {
			return " or held out of the pool by their reserve"
		}
	}
	return ""
}

// reserveBackLocked is when a reserved subscription is next in the pool: its weekly reset for a reserve
// below 100 (zero when no reset is known), never (zero) for 100.
func (s *backendSeriesSelector) reserveBackLocked(authID string) time.Time {
	if s.profileReserveLocked(authID) >= 100 {
		return time.Time{}
	}
	return s.currentQuotaLocked(authID).resetsAt
}

// reserveRefusalLocked: this request cannot leave a reserved subscription (opaque state bound to it):
// the 429 a rejected subscription gets, until the week resets, or in an hour when nothing but a change
// to the reserve file lifts it.
func (s *backendSeriesSelector) reserveRefusalLocked(authID string) *backendRefusalError {
	percent := s.profileReserveLocked(authID)
	back := s.reserveBackLocked(authID)
	refusal := &backendRefusalError{kind: backendRefusalQuota, authID: authID, resetAt: back}
	name := s.profileNameLocked(authID)
	if back.IsZero() {
		refusal.resetAt = s.nowOrReal().Add(profileReserveRetryAfter)
	}
	if percent >= 100 {
		refusal.reason = fmt.Sprintf("subscription %s is held out of the pool (reserve 100%%), and this conversation's state is bound to it and cannot move to another subscription; start a new conversation", name)
	} else {
		refusal.reason = fmt.Sprintf("subscription %s has reached its reserve (%d%% of its week held out of the pool; %v%% used), and this conversation's state is bound to it and cannot move to another subscription; it returns at the weekly reset, or start a new conversation", name, percent, usedPct(s.currentQuotaLocked(authID)))
	}
	return refusal
}

// noteReserveLocked logs, once per change, a subscription entering or leaving reserve-out.
func (s *backendSeriesSelector) noteReserveLocked(authID string, out bool, percent int, q backendWeeklyQuota) {
	if s.reserveOut == nil {
		if !out {
			return
		}
		s.reserveOut = make(map[string]bool, len(s.authIDs))
	}
	if s.reserveOut[authID] == out {
		return
	}
	if out {
		s.reserveOut[authID] = true
		lg().Info("profile held in reserve: out of the pool", "profile", s.profileNameLocked(authID),
			"reserve_pct", percent, "threshold_pct", 100-percent, "used_pct", usedPct(q), "resets_in", s.resetsIn(q))
		return
	}
	delete(s.reserveOut, authID)
	lg().Info("profile released from reserve: back in the pool", "profile", s.profileNameLocked(authID),
		"reserve_pct", percent, "threshold_pct", 100-percent, "used_pct", usedPct(q), "resets_in", s.resetsIn(q))
}
