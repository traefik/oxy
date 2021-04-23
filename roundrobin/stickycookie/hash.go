package stickycookie

import (
	"fmt"
	"net/url"

	"github.com/segmentio/fasthash/fnv1a"
)

func hash(input string) string {
	return fmt.Sprintf("%x", fnv1a.HashString64(input))
}

type HashManager struct{}

func (o *HashManager) ToValue(raw string) string {
	return hash(raw)
}

func normalized(u *url.URL) string {
	normalized := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return normalized.String()
}

func (o *HashManager) FindURL(raw string, urls []*url.URL) *url.URL {
	for _, u := range urls {
		if raw == hash(normalized(u)) {
			return u
		}
	}

	return nil
}
