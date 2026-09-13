package claudemaster

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestProfileNamesValidateBeforeOpeningAnything(t *testing.T) {
	for _, names := range [][]string{nil, {"ok", "../bad"}, {"first", "first"}, {"a", ""}, make([]string, MaxFallbackProfiles+1)} {
		called := false
		_, err := openProfiles(names, func(string) (*ProfileLock, error) {
			called = true
			return nil, errors.New("should not open")
		})
		if err == nil || called {
			t.Fatalf("invalid names reached filesystem: %q", names)
		}
	}
}

func TestProfileSetOrderOwnershipAndRelease(t *testing.T) {
	root := filepath.Join(canonicalTestTempDir(t), "profiles")
	for _, name := range []string{"third", "first", "second"} {
		lock, err := openProfileAt(root, name, true)
		if err != nil {
			t.Fatal(err)
		}
		installProfileFixture(t, lock)
		_ = lock.Close()
	}
	opener := func(name string) (*ProfileLock, error) { return openProfileAt(root, name, false) }
	names := []string{"third", "first", "second"}
	set, err := openProfiles(names, opener)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	var got []string
	for _, profile := range set.Profiles() {
		got = append(got, profile.Name)
		if lock, err := opener(profile.Name); err == nil {
			_ = lock.Close()
			t.Fatal("candidate not exclusively held")
		}
	}
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("order changed: %v", got)
	}
	copy := set.Profiles()
	copy[0].Name = "mutation"
	if set.Profiles()[0].Name != "third" {
		t.Fatal("profile list aliases caller slice")
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		lock, err := opener(name)
		if err != nil {
			t.Fatal("candidate lock leaked", err)
		}
		_ = lock.Close()
	}
}

func TestProfileSetPartialFailureReleasesAllAcquiredLocks(t *testing.T) {
	for _, failure := range []string{"busy", "missing", "invalid"} {
		t.Run(failure, func(t *testing.T) {
			root := filepath.Join(canonicalTestTempDir(t), "profiles")
			first, err := openProfileAt(root, "first", true)
			if err != nil {
				t.Fatal(err)
			}
			installProfileFixture(t, first)
			_ = first.Close()
			if failure != "missing" {
				second, err := openProfileAt(root, "second", true)
				if err != nil {
					t.Fatal(err)
				}
				if failure == "busy" {
					installProfileFixture(t, second)
					t.Cleanup(func() { _ = second.Close() })
				} else {
					_ = second.Close()
				}
			}
			opener := func(name string) (*ProfileLock, error) { return openProfileAt(root, name, false) }
			if set, err := openProfiles([]string{"first", "second"}, opener); err == nil {
				_ = set.Close()
				t.Fatal("unavailable candidate was ignored")
			}
			lock, err := opener("first")
			if err != nil {
				t.Fatal("earlier profile lock leaked", err)
			}
			_ = lock.Close()
			if failure == "invalid" {
				lock, err := opener("second")
				if err != nil {
					t.Fatal("invalid profile lock leaked", err)
				}
				_ = lock.Close()
			}
		})
	}
}

func TestProfileBackendOptionsPreserveOrderAndRejectMixedProviders(t *testing.T) {
	profiles := []Profile{{Name: "primary", Provider: "claude", AuthID: "a.json", AuthDir: "/private/a"}, {Name: "secondary", Provider: "claude", AuthID: "b.json", AuthDir: "/private/b"}}
	opts, err := profileBackendOptions(profiles, "claude-sonnet-4-6")
	if err != nil || len(opts) != 2 || opts[0].AuthID != "a.json" || opts[1].AuthID != "b.json" || opts[1].Model != "claude-sonnet-4-6" {
		t.Fatalf("invalid backend options: %v %v", opts, err)
	}
	profiles[1].Provider = "codex"
	if _, err := profileBackendOptions(profiles, "claude-sonnet-4-6"); err == nil {
		t.Fatal("mixed provider chain accepted")
	}
	if _, err := profileBackendOptions(nil, "model"); err == nil {
		t.Fatal("empty chain accepted")
	}
}
