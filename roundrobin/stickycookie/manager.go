package stickycookie

import "net/url"

type CookieManager interface {
	ToValue(string) string

	FindURL(string, []*url.URL) *url.URL
}

// DefaultManager is a no-op that returns the raw/obfuscated strings as-is
type DefaultManager struct{}

func (o *DefaultManager) ToValue(raw string) string {
	return raw
}

// AreEqual takes two string and check if the values are equal
func areEqual(normalized string, u *url.URL) bool {
	u1, err := url.Parse(normalized)
	if err != nil {
		return false
	}

	return u1.Scheme == u.Scheme && u1.Host == u.Host && u1.Path == u.Path
}

func (o *DefaultManager) FindURL(raw string, urls []*url.URL) *url.URL {
	for _, u := range urls {
		if areEqual(raw, u) {
			return u
		}
	}

	return nil
}
