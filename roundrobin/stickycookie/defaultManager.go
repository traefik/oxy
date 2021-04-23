package stickycookie

import (
	"net/url"
)

// DefaultManager is a no-op that returns the raw strings as-is.
type DefaultManager struct{}

// ToValue return the raw value.
func (o *DefaultManager) ToValue(raw string) string {
	return raw
}

// areEqual compare a string to a url and check if the string is the same as the url value.
func areEqual(normalized string, u *url.URL) bool {
	u1, err := url.Parse(normalized)
	if err != nil {
		return false
	}

	return u1.Scheme == u.Scheme && u1.Host == u.Host && u1.Path == u.Path
}

// FindURL get url from array that match the value.
func (o *DefaultManager) FindURL(raw string, urls []*url.URL) *url.URL {
	for _, u := range urls {
		if areEqual(raw, u) {
			return u
		}
	}

	return nil
}
