package stickycookie

import (
	"net/url"
)

// RawValue is a no-op that returns the raw strings as-is.
type RawValue struct{}

// ToValue return the raw value.
func (v *RawValue) ToValue(raw string) string {
	return raw
}

// FindURL get url from array that match the value.
func (v *RawValue) FindURL(raw string, urls []*url.URL) (*url.URL, error) {
	for _, u := range urls {
		ok, err := areURLEqual(raw, u)
		if err != nil {
			return nil, err
		}

		if ok {
			return u, nil
		}
	}

	return nil, nil
}
