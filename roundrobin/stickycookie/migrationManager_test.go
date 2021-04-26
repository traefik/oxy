package stickycookie

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {

	servers := []*url.URL{
		{Scheme: "http", Host: "10.10.10.10", Path: "/"},
		{Scheme: "https", Host: "10.10.10.42", Path: "/"},
		{Scheme: "http", Host: "10.10.10.10", Path: "/foo"},
		{Scheme: "http", Host: "10.10.10.11", Path: "/", User: url.User("John Doe")},
	}

	hashManager := &HashManager{Salt: "foo"}
	defaultManager := &DefaultManager{}
	aesManager, err := NewAESManager([]byte("95Bx9JkKX3xbd7z3"), 5*time.Second)
	require.NoError(t, err)

	tests := []struct {
		name          string
		CookieManager CookieManager
		rawValue      string
		want          *url.URL
		expectError   bool
	}{
		{
			name: "From DefaultManager to HashManager with DefaultManager value",
			CookieManager: &MigrationManager{
				From: defaultManager,
				To:   hashManager,
			},
			rawValue: "http://10.10.10.10/",
			want:     servers[0],
		},
		{
			name: "From DefaultManager to HashManager with DefaultManager non matching value",
			CookieManager: &MigrationManager{
				From: defaultManager,
				To:   hashManager,
			},
			rawValue: "http://24.10.10.10/",
		},
		{
			name: "From DefaultManager to HashManager with HashManager value",
			CookieManager: &MigrationManager{
				From: defaultManager,
				To:   hashManager,
			},
			rawValue: hashManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name: "From DefaultManager to HashManager with HashManager non matching value",
			CookieManager: &MigrationManager{
				From: defaultManager,
				To:   hashManager,
			},
			rawValue: hashManager.ToValue("http://24.10.10.10/"),
		},
		{
			name: "From HashManager to AESManager with aesManager value",
			CookieManager: &MigrationManager{
				From: hashManager,
				To:   aesManager,
			},
			rawValue: aesManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name: "From HashManager to AESManager with aesManager non matching value",
			CookieManager: &MigrationManager{
				From: hashManager,
				To:   aesManager,
			},
			rawValue: aesManager.ToValue("http://24.10.10.10/"),
		},
		{
			name: "From HashManager to AESManager with AESManager value",
			CookieManager: &MigrationManager{
				From: hashManager,
				To:   aesManager,
			},
			rawValue: hashManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name: "From HashManager to AESManager with AESManager non matching value",
			CookieManager: &MigrationManager{
				From: hashManager,
				To:   aesManager,
			},
			rawValue: hashManager.ToValue("http://24.10.10.10/"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findURL, err := tt.CookieManager.FindURL(tt.rawValue, servers)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, findURL)
		})
	}
}
