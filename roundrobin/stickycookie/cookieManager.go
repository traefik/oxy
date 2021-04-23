package stickycookie

import "net/url"

// CookieManager interface to manage the sticky cookie value format.
// It will be used by the load balancer to generate the sticky cookie value and to retrieve the matching url.
// There is two implementations of this interface:
//  - DefaultManager: that uses a no/op operation.
//  - HashManager: that hashes the value using a fast hash algorithm.
type CookieManager interface {
	// ToValue convert raw value to an expected sticky format.
	ToValue(string) string

	// FindURL get url from array that match the value.
	FindURL(string, []*url.URL) *url.URL
}
