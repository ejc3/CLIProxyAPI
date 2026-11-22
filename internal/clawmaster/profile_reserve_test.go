package clawmaster

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// A profile reserve holds the last N% of a subscription's week out of the pool: out once the weekly
// usage reaches (100 - N)%, always at 100. It is the one opt-in exception to "the poll is advisory".

func TestParseProfileReservesReadsProfileEqualsPercentLines(t *testing.T) {
	got, err := ParseProfileReserves([]byte("# kept for its owner\nclaude-kept-20261112=100\n\n  claude-secondary = 30 \n\t# indented comment\nclaude-third=0\nclaude-fourth=007\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"claude-kept-20261112": 100, "claude-secondary": 30, "claude-third": 0, "claude-fourth": 7}
	if !maps.Equal(got, want) {
		t.Fatalf("reserves = %v, want %v", got, want)
	}
	if got, err := ParseProfileReserves(nil); err != nil || len(got) != 0 {
		t.Fatalf("an empty file = %v, %v, want no reserves", got, err)
	}
	if got, err := ParseProfileReserves([]byte("# only comments\n\n")); err != nil || len(got) != 0 {
		t.Fatalf("a comment-only file = %v, %v, want no reserves", got, err)
	}
}

func TestParseProfileReservesRefusesEveryInvalidLine(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no equals", "claude-a 30\n", "line 1: a profile reserve must be PROFILE=N"},
		{"no profile", "=30\n", "line 1: a profile reserve must be PROFILE=N"},
		{"bad profile name", "-claude=30\n", "line 1: a profile reserve must be PROFILE=N"},
		{"profile with a space", "claude a=30\n", "line 1: a profile reserve must be PROFILE=N"},
		{"no percent", "claude-a=\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"over 100", "claude-a=101\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"far over 100", "claude-a=1000\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"negative", "claude-a=-1\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"plus sign", "claude-a=+5\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"fraction", "claude-a=12.5\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"percent sign", "claude-a=30%\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"trailing comment", "claude-a=30 # mine\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"two equals", "claude-a=30=40\n", "line 1: the reserve of claude-a must be a whole percent from 0 to 100"},
		{"duplicate", "claude-a=30\n# again\nclaude-a=30\n", "line 3: claude-a is named twice"},
		{"bad line after good ones", "claude-a=30\nclaude-b=40\nnonsense\n", "line 3: a profile reserve must be PROFILE=N"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseProfileReserves([]byte(tc.body))
			if err == nil || got != nil {
				t.Fatalf("ParseProfileReserves(%q) = %v, %v, want an error", tc.body, got, err)
			}
			if err.Error() != tc.want {
				t.Fatalf("error = %q, want %q", err.Error(), tc.want)
			}
		})
	}
	// The error never echoes the line: a stray secret pasted into the file does not reach the log.
	if _, err := ParseProfileReserves([]byte("sk-ant-secret-value\n")); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error = %v, want one that does not quote the line", err)
	}
	if _, err := LoadProfileReserves(filepath.Join(t.TempDir(), "missing")); err == nil || err.Error() != "cannot read --profile-reserve-file" {
		t.Fatalf("a missing file = %v", err)
	}
}

// setProfileReservesForTest installs reserves and puts back an empty set afterwards.
func setProfileReservesForTest(t *testing.T, reserves map[string]int) {
	t.Helper()
	SetProfileReserves(reserves)
	t.Cleanup(func() { SetProfileReserves(nil) })
}

func TestSetProfileReservesReportsAChange(t *testing.T) {
	t.Cleanup(func() { SetProfileReserves(nil) })
	SetProfileReserves(nil)
	if SetProfileReserves(map[string]int{}) {
		t.Fatal("no reserves to no reserves reported a change")
	}
	if !SetProfileReserves(map[string]int{"reserve-set-a": 30}) {
		t.Fatal("a new reserve was not reported")
	}
	if SetProfileReserves(map[string]int{"reserve-set-a": 30}) {
		t.Fatal("the same reserves reported a change")
	}
	if !SetProfileReserves(map[string]int{"reserve-set-a": 40}) || profileReserveFor("reserve-set-a") != 40 {
		t.Fatal("a changed reserve was not applied")
	}
	if profileReserveFor("reserve-set-other") != 0 {
		t.Fatal("a profile with no line has a reserve")
	}
}

func replaceFile(t *testing.T, file, body string) {
	t.Helper()
	tmp := file + ".new"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, file); err != nil {
		t.Fatal(err)
	}
}

func waitForReserve(t *testing.T, name string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for profileReserveFor(name) != want {
		if time.Now().After(deadline) {
			t.Fatalf("reserve of %s = %d, want %d", name, profileReserveFor(name), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestProfileReservesReloadWhenTheFileChanges(t *testing.T) {
	logs := captureLogs(t, "info")
	setProfileReservesForTest(t, nil)
	file := filepath.Join(t.TempDir(), "reserves")
	replaceFile(t, file, "reserve-reload-a=100\n")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	StartProfileReserves(ctx, file, 10*time.Millisecond)
	if profileReserveFor("reserve-reload-a") != 100 {
		t.Fatal("the reserves were not loaded at start")
	}
	if out := logs.String(); !strings.Contains(out, "profile reserves loaded") || !strings.Contains(out, "reserve-reload-a=100") {
		t.Fatalf("the load was not logged with profile=N:\n%s", out)
	}

	replaceFile(t, file, "# changed\nreserve-reload-a=30\nreserve-reload-b=50\n")
	waitForReserve(t, "reserve-reload-a", 30)
	waitForReserve(t, "reserve-reload-b", 50)

	// A file that does not load keeps the reserves in use, and says why.
	replaceFile(t, file, "reserve-reload-a=30\nreserve-reload-a=60\n")
	time.Sleep(100 * time.Millisecond)
	if profileReserveFor("reserve-reload-a") != 30 || profileReserveFor("reserve-reload-b") != 50 {
		t.Fatal("a bad file replaced the reserves")
	}
	if out := logs.String(); !strings.Contains(out, "profile reserve file changed but was not loaded") || !strings.Contains(out, "named twice") {
		t.Fatalf("the refused reload was not logged with its reason:\n%s", out)
	}
	// A file that disappears keeps them too; the next good file is loaded.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if profileReserveFor("reserve-reload-a") != 30 {
		t.Fatal("a removed file dropped the reserves")
	}
	replaceFile(t, file, "reserve-reload-a=0\n")
	waitForReserve(t, "reserve-reload-a", 0)
	waitForReserve(t, "reserve-reload-b", 0)
}

func TestABadOrMissingReserveFileAtStartHoldsNothingBack(t *testing.T) {
	logs := captureLogs(t, "info")
	setProfileReservesForTest(t, nil)
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bad := filepath.Join(dir, "bad")
	replaceFile(t, bad, "reserve-start-a=101\n")
	StartProfileReserves(ctx, bad, 10*time.Millisecond)
	if profileReserveFor("reserve-start-a") != 0 {
		t.Fatal("a bad file at start held a profile back")
	}
	if out := logs.String(); !strings.Contains(out, "profile reserve file was not loaded") || !strings.Contains(out, "whole percent") {
		t.Fatalf("the bad file was not logged with its reason:\n%s", out)
	}
	// Missing at start, then written: it is loaded without a restart.
	missing := filepath.Join(dir, "later")
	StartProfileReserves(ctx, missing, 10*time.Millisecond)
	replaceFile(t, missing, "reserve-start-b=100\n")
	waitForReserve(t, "reserve-start-b", 100)
}

// reserveSelector is namedSelector (claude-primary on profile-a, claude-secondary on profile-b, one
// hour before profile-a's weekly reset) with its own reserves.
func reserveSelector(t *testing.T, reserves map[string]int) (*backendSeriesSelector, []*coreauth.Auth, time.Time) {
	t.Helper()
	selector, auths, reset := namedSelector(t)
	selector.reserveFor = func(name string) int { return reserves[name] }
	return selector, auths, reset
}

// opaqueRequest is a continuation carrying state that cannot leave its subscription.
func opaqueRequest(session string) coreexecutor.Options {
	opts := plainRequest(session)
	opts.OriginalRequest = []byte(`{"messages":[{"role":"assistant","content":[{"type":"compaction","content":"summary","signature":"opaque"}]}]}`)
	return opts
}

func bindSession(selector *backendSeriesSelector, opts coreexecutor.Options, authID string) {
	id, _ := backendSeriesSessionIDs(opts)
	selector.mu.Lock()
	selector.initializeLocked()
	selector.sessions.Set(id, authID)
	selector.mu.Unlock()
}

func requireQuotaRefusal(t *testing.T, err error, resetAt time.Time) *backendRefusalError {
	t.Helper()
	var refusal *backendRefusalError
	if !errors.As(err, &refusal) || refusal.kind != backendRefusalQuota {
		t.Fatalf("refusal = %v, want a quota refusal (Anthropic's 429)", err)
	}
	if !refusal.resetAt.Equal(resetAt) {
		t.Fatalf("refusal retry at %s, want %s", refusal.resetAt, resetAt)
	}
	return refusal
}

// A reserve of 100 is out whatever the poll says, known or not: never selected, a self-contained
// conversation moves off it, and opaque state bound to it gets the 429 a rejected subscription gets,
// with an hour's retry-after (only a change to the file lifts it).
func TestAFullReserveIsNeverSelected(t *testing.T) {
	logs := captureLogs(t, "info")
	selector, auths, reset := reserveSelector(t, map[string]int{"claude-primary": 100})
	now := selector.now()
	requireBackendSeriesPickWith(t, selector, plainRequest("new"), auths, "profile-b")
	// Still out with the poll calling it nearly empty and resetting first.
	selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 0.01, resetsAt: reset})
	selector.observeQuota("profile-b", backendWeeklyQuota{known: true, used: 0.8, resetsAt: reset.Add(48 * time.Hour)})
	requireBackendSeriesPickWith(t, selector, plainRequest("another"), auths, "profile-b")

	// A self-contained conversation bound to it moves.
	moving := plainRequest("moving")
	bindSession(selector, moving, "profile-a")
	requireBackendSeriesPickWith(t, selector, moving, auths, "profile-b")
	if out := logs.String(); !strings.Contains(out, "reason=reserved") {
		t.Fatalf("the move off a reserved subscription was not logged as reserved:\n%s", out)
	}

	// Opaque state bound to it is refused, as for a rejected subscription.
	opaque := opaqueRequest("opaque")
	bindSession(selector, opaque, "profile-a")
	_, err := selector.Pick(t.Context(), "claude", "", opaque, auths)
	refusal := requireQuotaRefusal(t, err, now.Add(profileReserveRetryAfter))
	if refusal.authID != "profile-a" || !strings.Contains(refusal.reason, "reserve 100%") {
		t.Fatalf("refusal = %#v, want one naming the reserve on profile-a", refusal)
	}
	if got := strings.Count(logs.String(), "profile held in reserve: out of the pool"); got != 1 {
		t.Fatalf("entering reserve logged %d times, want once:\n%s", got, logs.String())
	}
}

// A reserve of 30 takes the subscription out at 70% of its week and not below; the week's reset brings
// it back.
func TestAPartialReserveTakesTheSubscriptionOutAtItsThreshold(t *testing.T) {
	logs := captureLogs(t, "info")
	selector, auths, reset := reserveSelector(t, map[string]int{"claude-primary": 30})
	clock := selector.now()
	selector.now = func() time.Time { return clock }
	selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 0.69, resetsAt: reset})
	selector.observeQuota("profile-b", backendWeeklyQuota{known: true, used: 0.2, resetsAt: reset.Add(8 * 24 * time.Hour)})
	conversation := plainRequest("conversation")
	requireBackendSeriesPickWith(t, selector, conversation, auths, "profile-a")
	requireBackendSeriesPickWith(t, selector, plainRequest("below"), auths, "profile-a")

	selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 0.70, resetsAt: reset})
	if out := logs.String(); !strings.Contains(out, "profile held in reserve: out of the pool") ||
		!strings.Contains(out, "profile=claude-primary") || !strings.Contains(out, "used_pct=70") || !strings.Contains(out, "threshold_pct=70") {
		t.Fatalf("entering reserve was not logged with its used fraction and threshold:\n%s", out)
	}
	requireBackendSeriesPickWith(t, selector, plainRequest("at-threshold"), auths, "profile-b")
	requireBackendSeriesPickWith(t, selector, conversation, auths, "profile-b") // self-contained: moves

	opaque := opaqueRequest("opaque")
	bindSession(selector, opaque, "profile-a")
	_, err := selector.Pick(t.Context(), "claude", "", opaque, auths)
	requireQuotaRefusal(t, err, reset) // back at the weekly reset

	// The week resets: usage starts again at 0 and the subscription is back.
	clock = reset.Add(time.Minute)
	requireBackendSeriesPickWith(t, selector, plainRequest("next-week"), auths, "profile-a")
	if out := logs.String(); !strings.Contains(out, "profile released from reserve: back in the pool") {
		t.Fatalf("leaving reserve was not logged:\n%s", out)
	}
	if got := strings.Count(logs.String(), "profile held in reserve: out of the pool"); got != 1 {
		t.Fatalf("entering reserve logged %d times, want once:\n%s", got, logs.String())
	}
}

// Unknown weekly usage leaves a reserve below 100 in: without the poll, the poll stays advisory.
func TestAPartialReserveWithUnknownUsageStaysIn(t *testing.T) {
	selector, auths, _ := reserveSelector(t, map[string]int{"claude-primary": 99, "claude-secondary": 99})
	requireBackendSeriesPickWith(t, selector, plainRequest("unknown"), auths, "profile-a")
	selector.mu.Lock()
	reserved, exhausted := selector.reservedLocked("profile-a"), selector.subscriptionsExhaustedLocked()
	selector.mu.Unlock()
	if reserved || exhausted {
		t.Fatalf("unknown usage: reserved=%v exhausted=%v, want neither", reserved, exhausted)
	}
}

// A reserve of 0, or none, is the ordinary behaviour: a polled 100% does not take a subscription out.
func TestAZeroReserveIsTheOrdinaryBehaviour(t *testing.T) {
	selector, auths, reset := reserveSelector(t, map[string]int{"claude-primary": 0})
	selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 1, resetsAt: reset})
	selector.observeQuota("profile-b", backendWeeklyQuota{known: true, used: 1, resetsAt: reset.Add(time.Hour)})
	requireBackendSeriesPickWith(t, selector, plainRequest("polled-full"), auths, "profile-a")
}

// The API-key backup is never reserved; every subscription out by reserve is the "all out" path, which
// hands self-contained work to the backup as a full set of real rejections does.
func TestReservesNeverHoldTheAPIBackup(t *testing.T) {
	selector, auths, reset := backendAPIBackupTestSelector(t)
	selector.names = map[string]string{"subscription-a": "sub-a", "subscription-b": "sub-b", "api-backup": "api-backup"}
	selector.reserveFor = func(string) int { return 100 } // every name, the backup's included
	selector.observeQuota("subscription-a", backendWeeklyQuota{known: true, used: 0.1, resetsAt: reset})
	selector.mu.Lock()
	backupReserved := selector.reservedLocked("api-backup")
	exhausted := selector.subscriptionsExhaustedLocked()
	selector.mu.Unlock()
	if backupReserved || !exhausted {
		t.Fatalf("backup reserved=%v, all subscriptions out=%v; want false, true", backupReserved, exhausted)
	}
	requireBackendAPIBackupPick(t, selector, backendAPIBackupTestOptions("all-reserved", false), auths, "api-backup")
}

// With every subscription out, by reserve or by Anthropic's 429, and no backup, the pool answers the
// 429 it answers when Anthropic rejected them all, at the earliest return.
func TestEverySubscriptionOutByReserveOrRejectionIsTheAllOutPath(t *testing.T) {
	selector, auths, reset := reserveSelector(t, map[string]int{"claude-primary": 30})
	now := selector.now()
	selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 0.8, resetsAt: reset})
	rejectByAnthropic(selector, "profile-b", 3*time.Hour)
	_, err := selector.Pick(t.Context(), "claude", "", plainRequest("all-out"), auths)
	requireQuotaRefusal(t, err, reset) // profile-a's weekly reset, an hour away, is the earliest return

	// Rejected by Anthropic AND past its reserve: back at the later of the two.
	rejectByAnthropic(selector, "profile-a", 2*time.Hour)
	_, err = selector.Pick(t.Context(), "claude", "", plainRequest("all-out-2"), auths)
	requireQuotaRefusal(t, err, now.Add(2*time.Hour))

	// Every subscription reserved at 100: nothing comes back by itself; retry in an hour.
	full, fullAuths, _ := reserveSelector(t, map[string]int{"claude-primary": 100, "claude-secondary": 100})
	_, err = full.Pick(t.Context(), "claude", "", plainRequest("all-full"), fullAuths)
	refusal := requireQuotaRefusal(t, err, full.now().Add(profileReserveRetryAfter))
	if !strings.Contains(refusal.reason, "rate limited") || !strings.Contains(refusal.reason, "held out of the pool by their reserve") {
		t.Fatalf("all-out reason = %q, want the ordinary all-out refusal", refusal.reason)
	}
}

// The selector reads the reserves loaded from the file when no test override is set.
func TestTheSelectorUsesTheLoadedReserves(t *testing.T) {
	setProfileReservesForTest(t, map[string]int{"claude-primary": 100})
	selector, auths, _ := namedSelector(t)
	requireBackendSeriesPickWith(t, selector, plainRequest("loaded"), auths, "profile-b")
	SetProfileReserves(nil)
	requireBackendSeriesPickWith(t, selector, plainRequest("cleared"), auths, "profile-a")
}

// claw_master.quota.reserved is 1 while a reserve holds a profile out, 0 while it does not, and absent for
// a profile with no reserve.
func TestTheReservedGaugeShowsWhichProfilesAReserveHoldsOut(t *testing.T) {
	reader := startMetrics(t, nil)
	selector, _, reset := reserveSelector(t, map[string]int{"claude-primary": 100})
	selector.observeQuota("profile-b", backendWeeklyQuota{known: true, used: 0.5, resetsAt: reset})
	src := &fixedSource{snap: selector.metricsSnapshot(nil)}
	registerStateSource(src)
	t.Cleanup(func() { unregisterStateSource(src) })
	rm := collect(t, reader)
	if v, ok := gaugeOf(rm, "claw_master.quota.reserved", map[string]string{"profile": "claude-primary"}); !ok || v != 1 {
		t.Errorf("reserved gauge for the reserved profile = %v (%v), want 1", v, ok)
	}
	if _, ok := gaugeOf(rm, "claw_master.quota.reserved", map[string]string{"profile": "claude-secondary"}); ok {
		t.Error("a profile with no reserve has a reserved gauge")
	}
}
