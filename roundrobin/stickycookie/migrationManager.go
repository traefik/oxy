package stickycookie

import (
	"net/url"
)

var _ CookieManager = (*MigrationManager)(nil)

// MigrationManager manage hashed sticky value.
type MigrationManager struct {
	From CookieManager
	To   CookieManager
}

// ToValue hashes the sticky value.
func (mm *MigrationManager) ToValue(raw string) string {
	return mm.To.ToValue(raw)
}

// FindURL get url from array that match the value.
// If it is a symmetric algorithm, it decodes the URL, otherwise it compares the ciphered values.
func (mm *MigrationManager) FindURL(raw string, urls []*url.URL) (*url.URL, error) {
	findURL, err := mm.From.FindURL(raw, urls)
	if findURL != nil {
		return findURL, err
	}

	return mm.To.FindURL(raw, urls)
}
