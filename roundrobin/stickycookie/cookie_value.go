package stickycookie

import "net/url"

// CookieValue interface to manage the sticky cookie value format.
// It will be used by the load balancer to generate the sticky cookie value and to retrieve the matching url.
// There is several implementations of this interface:
//  - RawValue: that uses a no/op operation.
//  - HashValue: that hashes the value using a fast hash algorithm.
//  - AESValue: that ciphers the value using an AES algorithm.
type CookieValue interface {
	// Get convert raw value to an expected sticky format.
	Get(*url.URL) string

	// FindURL get url from array that match the value.
	FindURL(string, []*url.URL) (*url.URL, error)
}

// areURLEqual compare a string to a url and check if the string is the same as the url value.
func areURLEqual(normalized string, u *url.URL) (bool, error) {
	u1, err := url.Parse(normalized)
	if err != nil {
		return false, err
	}

	return u1.Scheme == u.Scheme && u1.Host == u.Host && u1.Path == u.Path, nil
}
