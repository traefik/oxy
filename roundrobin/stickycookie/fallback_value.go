package stickycookie

import (
	"errors"
	"net/url"
)

// FallbackValue manage hashed sticky value.
type FallbackValue struct {
	From CookieValue
	To   CookieValue
}

// NewMigrationManager creates a new FallbackValue
func NewMigrationManager(from CookieValue, to CookieValue) (CookieValue, error) {
	if from == nil && to == nil {
		return nil, errors.New("no CookieValue defined")
	}

	if from == nil {
		return to, nil
	}

	if to == nil {
		return from, nil
	}

	return &FallbackValue{From: from, To: to}, nil
}

// ToValue hashes the sticky value.
func (v *FallbackValue) ToValue(raw string) string {
	return v.To.ToValue(raw)
}

// FindURL get url from array that match the value.
// If it is a symmetric algorithm, it decodes the URL, otherwise it compares the ciphered values.
func (v *FallbackValue) FindURL(raw string, urls []*url.URL) (*url.URL, error) {
	findURL, err := v.From.FindURL(raw, urls)
	if findURL != nil {
		return findURL, err
	}

	return v.To.FindURL(raw, urls)
}
