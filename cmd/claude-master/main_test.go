package main

import "testing"

func TestInvalidArgumentsStopBeforeProfileOrLogin(t *testing.T) {
	for _, args := range [][]string{
		nil, {"help"}, {"unknown", "profile"}, {"login", "profile"},
		{"login", "profile", "--provider", "unknown"},
		{"login", "profile", "--provider", "claude", "--model", "test"},
		{"login", "profile", "--provider", "claude", "--", "unexpected"},
		{"run", "profile"}, {"run", "profile", "--provider", "claude", "--model", "test"},
		{"run", "profile", "--unknown-secret=canary"},
		{"probe", "profile"}, {"probe", "profile", "--model", "test", "--", "unexpected"},
		{"probe", "profile", "--model", "test", "--diagnostics"},
		{"login", "profile", "--provider", "claude", "--diagnostics"},
		{"login", "profile", "--provider", "claude", "--fallback-profile", "other"},
		{"probe", "profile", "--model", "test", "--fallback-profile", "other"},
		{"run", "profile", "--model", "test", "--fallback-profile", "profile"},
		{"run", "profile", "--model", "test", "--fallback-profile", "../other"},
		{"run", "profile", "--model", "test", "--fallback-profile", ""},
		{"run", "profile", "--model", "test", "--fallback-profile"},
	} {
		code, err := run(args)
		if err == nil || code != 2 {
			t.Fatalf("invalid command accepted: %q, code=%d, err=%v", args, code, err)
		}
	}
}

func TestRepeatedProfileFlagRetainsOrder(t *testing.T) {
	var profiles profileNamesFlag
	for _, name := range []string{"second", "third", "fourth"} {
		if err := profiles.Set(name); err != nil {
			t.Fatal(err)
		}
	}
	if profiles.String() != "second,third,fourth" {
		t.Fatalf("profile order lost: %v", profiles)
	}
}
