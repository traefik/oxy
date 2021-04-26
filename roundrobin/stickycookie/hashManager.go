package stickycookie

import (
	"fmt"
	"net/url"

	"github.com/segmentio/fasthash/fnv1a"
)

var _ CookieManager = (*HashManager)(nil)

// HashManager manage hashed sticky value.
type HashManager struct {
	// Salt secret to anonymize the hashed cookie
	Salt string
}

func (hm *HashManager) hash(input string) string {
	return fmt.Sprintf("%x", fnv1a.HashString64(hm.Salt+input))
}

// ToValue hashes the sticky value.
func (hm *HashManager) ToValue(raw string) string {
	return hm.hash(raw)
}

func normalized(u *url.URL) string {
	normalized := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return normalized.String()
}

// FindURL get url from array that match the value.
func (hm *HashManager) FindURL(raw string, urls []*url.URL) (*url.URL, error) {
	for _, u := range urls {
		if raw == hm.hash(normalized(u)) {
			return u, nil
		}
	}

	return nil, nil
}
