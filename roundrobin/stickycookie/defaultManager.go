package stickycookie

import (
	"net/url"
)

var _ CookieManager = (*DefaultManager)(nil)

// DefaultManager is a no-op that returns the raw strings as-is.
type DefaultManager struct{}

// ToValue return the raw value.
func (dm *DefaultManager) ToValue(raw string) string {
	return raw
}

// FindURL get url from array that match the value.
func (dm *DefaultManager) FindURL(raw string, urls []*url.URL) (*url.URL, error) {
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
