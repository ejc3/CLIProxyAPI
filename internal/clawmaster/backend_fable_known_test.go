package clawmaster

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The headers of a 429 Anthropic sent a Fable request on a subscription with no five-hour window, where
// the header detector does not see a Fable-only refusal: the unified status rejected and the week allowed,
// with no five-hour status or utilization at all. The executor marks such a 429 credential-scoped.
func fable429WithoutFiveHourHeaders(weekReset time.Time) http.Header {
	h := http.Header{}
	h.Set("Anthropic-Ratelimit-Unified-Status", "rejected")
	h.Set("Anthropic-Ratelimit-Unified-Representative-Claim", "seven_day_overage_included")
	h.Set("Anthropic-Ratelimit-Unified-7d-Status", "allowed")
	h.Set("Anthropic-Ratelimit-Unified-Reset", strconv.FormatInt(weekReset.Unix(), 10))
	h.Set("Retry-After", strconv.Itoa(int(time.Until(weekReset).Seconds())))
	return h
}

func applyFable429(t *testing.T, manager *coreauth.Manager, authID, model string, headers http.Header, retryAfter time.Duration) {
	t.Helper()
	ctx := withBackendAttempt(withResponseHeaders(headers))
	manager.ResultPolicy().ApplyResultPolicy(ctx, coreauth.Result{
		AuthID: authID, Model: model, CredentialScope: true, RetryAfter: &retryAfter,
		Error: &coreauth.Error{HTTPStatus: http.StatusTooManyRequests},
	})
}

// A Fable request's 429 on a subscription whose Fable allowance the pool knows is used up, with its week
// well short of the limit, holds the subscription back from Fable only, whatever the headers say: Anthropic
// keeps serving every other model there.
func TestFable429AtAUsedUpFableAllowanceHoldsBackFableOnly(t *testing.T) {
	logs := captureLogs(t, "info")
	selector, auths, reset := namedSelector(t)
	now := reset.Add(-150 * time.Hour)
	selector.now = func() time.Time { return now }
	selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 0.74, resetsAt: reset})
	selector.observeQuota("profile-b", backendWeeklyQuota{known: true, used: 0.90, resetsAt: reset})
	selector.observePolledFable("profile-a", ClaudeFableQuota{UsedFraction: 0.97, ResetsAt: reset}, selector.fablePollRevision("profile-a"))
	manager := coreauth.NewManager(nil, selector, nil)
	setBackendSeriesResultPolicy(manager, selector)

	applyFable429(t, manager, "profile-a", testFableModel, fable429WithoutFiveHourHeaders(reset), reset.Sub(now))

	selector.mu.Lock()
	fableBlocked, weeklyBlocked := selector.fableBlockedLocked("profile-a"), selector.quotaBlockedLocked("profile-a")
	until := selector.fableBlockedUntil["profile-a"]
	selector.mu.Unlock()
	if !fableBlocked || weeklyBlocked || !until.Equal(reset) {
		t.Fatalf("fable blocked %v until %v, whole subscription blocked %v; want Fable only, until %v", fableBlocked, until, weeklyBlocked, reset)
	}
	requirePickModel(t, selector, auths, "opus", testOtherModel, "profile-a")
	requirePickModel(t, selector, auths, "fable", testFableModel, "profile-b")
	out := logs.String()
	if !strings.Contains(out, "Anthropic refused a Fable request") || !strings.Contains(out, "held=fable") ||
		!strings.Contains(out, "Anthropic-Ratelimit-Unified-7d-Status=allowed") {
		t.Errorf("the refusal's headers were not logged:\n%s", out)
	}
}

// A genuine refusal of the whole subscription stays a whole-subscription hold: the week (or the five-hour
// window) used up or rejected, or a Fable allowance the pool does not know to be used up.
func TestFable429OfAUsedUpWindowStillHoldsTheWholeSubscription(t *testing.T) {
	cases := []struct {
		name      string
		week      float64
		fable     float64
		fiveHour  float64
		headerFor func(time.Time) http.Header
	}{
		{"the week used up", 0.99, 1, 0, fable429WithoutFiveHourHeaders},
		{"the week rejected", 0.74, 1, 0, func(r time.Time) http.Header {
			h := fable429WithoutFiveHourHeaders(r)
			h.Set("Anthropic-Ratelimit-Unified-7d-Status", "rejected")
			return h
		}},
		{"the five-hour window rejected", 0.74, 1, 0, func(r time.Time) http.Header {
			h := fable429WithoutFiveHourHeaders(r)
			h.Set("Anthropic-Ratelimit-Unified-5h-Status", "rejected")
			return h
		}},
		{"the five-hour window used up", 0.74, 1, 1, fable429WithoutFiveHourHeaders},
		{"Fable not used up", 0.74, 0.60, 0, fable429WithoutFiveHourHeaders},
		{"the 429 says the week is used up", 0.74, 1, 0, func(r time.Time) http.Header {
			h := fable429WithoutFiveHourHeaders(r)
			h.Set("Anthropic-Ratelimit-Unified-7d-Utilization", "1.0")
			h.Set("Anthropic-Ratelimit-Unified-7d-Reset", strconv.FormatInt(r.Unix(), 10))
			return h
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selector, _, reset := namedSelector(t)
			now := reset.Add(-150 * time.Hour)
			selector.now = func() time.Time { return now }
			selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: tc.week, resetsAt: reset})
			selector.observePolledFable("profile-a", ClaudeFableQuota{UsedFraction: tc.fable, ResetsAt: reset}, selector.fablePollRevision("profile-a"))
			if tc.fiveHour > 0 {
				selector.observeFiveHourQuota("profile-a", ClaudeFiveHourQuota{UsedFraction: tc.fiveHour, ResetsAt: now.Add(time.Hour)})
			}
			manager := coreauth.NewManager(nil, selector, nil)
			setBackendSeriesResultPolicy(manager, selector)

			applyFable429(t, manager, "profile-a", testFableModel, tc.headerFor(reset), reset.Sub(now))

			selector.mu.Lock()
			fableBlocked, weeklyBlocked := selector.fableBlockedLocked("profile-a"), selector.quotaBlockedLocked("profile-a")
			selector.mu.Unlock()
			if fableBlocked || !weeklyBlocked {
				t.Fatalf("fable blocked %v, whole subscription blocked %v; want the whole subscription", fableBlocked, weeklyBlocked)
			}
		})
	}

	// Another model's 429 is never read as a Fable refusal.
	selector, _, reset := namedSelector(t)
	now := reset.Add(-150 * time.Hour)
	selector.now = func() time.Time { return now }
	selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 0.74, resetsAt: reset})
	selector.observePolledFable("profile-a", ClaudeFableQuota{UsedFraction: 1, ResetsAt: reset}, selector.fablePollRevision("profile-a"))
	manager := coreauth.NewManager(nil, selector, nil)
	setBackendSeriesResultPolicy(manager, selector)
	applyFable429(t, manager, "profile-a", testOtherModel, fable429WithoutFiveHourHeaders(reset), reset.Sub(now))
	selector.mu.Lock()
	fableBlocked, weeklyBlocked := selector.fableBlockedLocked("profile-a"), selector.quotaBlockedLocked("profile-a")
	selector.mu.Unlock()
	if fableBlocked || !weeklyBlocked {
		t.Fatalf("another model's 429: fable blocked %v, whole subscription blocked %v", fableBlocked, weeklyBlocked)
	}
}

// A 429 whose headers say the Fable allowance and the unified limit are still allowed (a per-minute limit,
// say) is not read as a used-up Fable allowance, however close to its limit the pool's last Fable reading is:
// it must not hold Fable back until the weekly reset.
func TestFable429WithFableStillAllowedIsNotAFableHold(t *testing.T) {
	for _, status := range []string{"allowed", "allowed_warning"} {
		t.Run(status, func(t *testing.T) {
			selector, _, reset := namedSelector(t)
			now := reset.Add(-150 * time.Hour)
			selector.now = func() time.Time { return now }
			selector.observeQuota("profile-a", backendWeeklyQuota{known: true, used: 0.74, resetsAt: reset})
			selector.observePolledFable("profile-a", ClaudeFableQuota{UsedFraction: 0.97, ResetsAt: reset}, selector.fablePollRevision("profile-a"))
			manager := coreauth.NewManager(nil, selector, nil)
			setBackendSeriesResultPolicy(manager, selector)

			h := http.Header{}
			h.Set("Anthropic-Ratelimit-Unified-Status", status)
			h.Set("Anthropic-Ratelimit-Unified-7d_oi-Status", status)
			h.Set("Anthropic-Ratelimit-Unified-Representative-Claim", "seven_day_overage_included")
			h.Set("Retry-After", "30")
			applyFable429(t, manager, "profile-a", testFableModel, h, 30*time.Second)

			selector.mu.Lock()
			fableBlocked, until := selector.fableBlockedLocked("profile-a"), selector.fableBlockedUntil["profile-a"]
			selector.mu.Unlock()
			if fableBlocked && !until.Before(reset) {
				t.Fatalf("a 429 with Fable %s held Fable back until %v, the weekly reset", status, until)
			}
		})
	}
}

// The logged headers carry only plain enums, numbers and timestamps; anything else is not printed.
func TestRateLimitHeaderSummaryPrintsOnlyPlainValues(t *testing.T) {
	h := http.Header{}
	h.Set("Anthropic-Ratelimit-Unified-Status", "rejected")
	h.Set("Anthropic-Ratelimit-Unified-Overage-Disabled-Reason", "org text \x1b[31m")
	h.Set("Retry-After", "120")
	h.Set("X-Other", "kept out")
	got := rateLimitHeaderSummary(h)
	want := "Anthropic-Ratelimit-Unified-Overage-Disabled-Reason=unrecognised Anthropic-Ratelimit-Unified-Status=rejected Retry-After=120"
	if got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
}
