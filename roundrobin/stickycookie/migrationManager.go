package stickycookie

import (
	"errors"
	"net/url"
)

var _ CookieManager = (*MigrationManager)(nil)

// MigrationManager manage hashed sticky value.
type MigrationManager struct {
	From CookieManager
	To   CookieManager
}

// NewMigrationManager creates a new MigrationManager
func NewMigrationManager(From CookieManager, To CookieManager) (CookieManager, error) {
	if From == nil && To == nil {
		return nil, errors.New("no CookieManager defined")
	}

	if From == nil {
		return To, nil
	}

	if To == nil {
		return From, nil
	}

	return &MigrationManager{
		From: From,
		To:   To,
	}, nil
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
