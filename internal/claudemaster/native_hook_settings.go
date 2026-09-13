package claudemaster

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Keep inline settings below per-argument OS limits. t-claude's generated hooks are tiny.
const hookSettingsByteLimit = 64 * 1024

// snapshotNativeHookSettings preserves local orchestration hooks without accepting a second
// provider/settings source. Files become immutable inline JSON before the child is started.
// Hooks are user-authorized local commands, not a security sandbox (just like native hooks).
func snapshotNativeHookSettings(args []string) ([]string, error) {
	out := append([]string(nil), args...)
	found := false
	for i := 0; i < len(out); i++ {
		if out[i] == "--" {
			break
		}
		if out[i] != "--settings" && !strings.HasPrefix(out[i], "--settings=") {
			continue
		}
		if found {
			return nil, errors.New("native hook settings may only be supplied once")
		}
		found = true
		equals := out[i] != "--settings"
		value := strings.TrimPrefix(out[i], "--settings=")
		if !equals {
			i++
			if i == len(out) {
				return nil, errors.New("native hook settings require a value")
			}
			value = out[i]
		}
		raw := []byte(strings.TrimSpace(value))
		if len(raw) == 0 || raw[0] != '{' {
			var err error
			raw, err = readNativeHookSettingsFile(value)
			if err != nil {
				return nil, err
			}
		}
		snapshot, err := nativeHookSettingsJSON(raw)
		if err != nil {
			return nil, err
		}
		if equals {
			out[i] = "--settings=" + snapshot
		} else {
			out[i] = snapshot
		}
	}
	return out, nil
}

func readNativeHookSettingsFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot open native hook settings as a regular unlinked file")
	}
	f := os.NewFile(uintptr(fd), "native hook settings")
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > hookSettingsByteLimit {
		return nil, errors.New("native hook settings must be a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, hookSettingsByteLimit+1))
	if err != nil || len(raw) > hookSettingsByteLimit {
		return nil, errors.New("cannot safely read native hook settings")
	}
	return raw, nil
}

func nativeHookSettingsJSON(raw []byte) (string, error) {
	if len(raw) > hookSettingsByteLimit {
		return "", errors.New("native hook settings exceed the size limit")
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(raw, &settings) != nil || settings == nil {
		return "", errors.New("native hook settings must be a JSON object")
	}
	for key, value := range settings {
		switch key {
		case "hooks":
			var hooks map[string]json.RawMessage
			if json.Unmarshal(value, &hooks) != nil || hooks == nil {
				return "", errors.New("native hooks must be an object")
			}
		case "preferredNotifChannel":
			var channel string
			if string(value) == "null" || json.Unmarshal(value, &channel) != nil {
				return "", errors.New("native notification channel must be a string")
			}
		default:
			return "", errors.New("explicit native settings may contain only hooks and preferredNotifChannel; provider and other settings overrides are not supported")
		}
	}
	// Marshal the inspected map instead of passing a possibly ambiguous duplicate-key source.
	snapshot, err := json.Marshal(settings)
	if err != nil || len(snapshot) > hookSettingsByteLimit {
		return "", errors.New("cannot snapshot native hook settings")
	}
	return string(snapshot), nil
}
