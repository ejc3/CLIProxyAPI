package claudemaster

import (
	"errors"
	"fmt"
)

// ProfileSet holds every candidate lock for the lifetime of a native session.
// Profiles remain in caller order; none is silently skipped if it cannot be opened.
type ProfileSet struct {
	profiles []Profile
	locks    []*ProfileLock
}

// ValidateProfileNames rejects invalid or repeated names before any filesystem access.
func ValidateProfileNames(names []string) error {
	if len(names) == 0 {
		return errors.New("at least one inference profile is required")
	}
	if len(names) > MaxFallbackProfiles {
		return errors.New("at most 16 inference profiles may be selected")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !profileName.MatchString(name) {
			return errors.New("profile name must be 1-64 letters, digits, underscores, or hyphens, starting with a letter or digit")
		}
		if seen[name] {
			return errors.New("each inference profile may only be selected once")
		}
		seen[name] = true
	}
	return nil
}

func OpenProfiles(names []string) (*ProfileSet, error) {
	return openProfiles(names, func(name string) (*ProfileLock, error) { return OpenProfile(name, false) })
}

func openProfiles(names []string, open func(string) (*ProfileLock, error)) (*ProfileSet, error) {
	if err := ValidateProfileNames(names); err != nil {
		return nil, err
	}
	set := &ProfileSet{}
	for i, name := range names {
		lock, err := open(name)
		if err != nil {
			_ = set.Close()
			return nil, fmt.Errorf("cannot open inference profile %d (%s): %w", i+1, name, err)
		}
		set.locks = append(set.locks, lock)
		profile, err := lock.Profile()
		if err != nil {
			_ = set.Close()
			return nil, fmt.Errorf("cannot load inference profile %d (%s): %w", i+1, name, err)
		}
		set.profiles = append(set.profiles, profile)
	}
	return set, nil
}

func (s *ProfileSet) Profiles() []Profile {
	return append([]Profile(nil), s.profiles...)
}

// Close releases all locks after the proxy, backends and refresh writers have stopped.
func (s *ProfileSet) Close() error {
	if s == nil {
		return nil
	}
	var result error
	for i := len(s.locks) - 1; i >= 0; i-- {
		result = errors.Join(result, s.locks[i].Close())
	}
	s.locks = nil
	return result
}
