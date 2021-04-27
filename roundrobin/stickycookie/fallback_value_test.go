package stickycookie

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	servers := []*url.URL{
		{Scheme: "https", Host: "10.10.10.42", Path: "/"},
		{Scheme: "http", Host: "10.10.10.10", Path: "/foo"},
		{Scheme: "http", Host: "10.10.10.11", Path: "/", User: url.User("John Doe")},
		{Scheme: "http", Host: "10.10.10.10", Path: "/"},
	}

	hashManager := &HashValue{Salt: "foo"}
	defaultManager := &RawValue{}
	aesManager, err := NewAESManager([]byte("95Bx9JkKX3xbd7z3"), 5*time.Second)
	require.NoError(t, err)

	managers := []struct {
		Name          string
		CookieManager CookieValue
	}{
		{"defaultManager", defaultManager},
		{"hashManager", hashManager},
		{"aesManager", aesManager},
		{"nil", nil},
	}

	for i := 0; i < len(managers); i++ {
		for j := 0; j < len(managers); j++ {
			from := managers[i]
			to := managers[j]

			t.Run(fmt.Sprintf("From: %s, To %s", from.Name, to.Name), func(t *testing.T) {

				manager, err := NewMigrationManager(from.CookieManager, to.CookieManager)
				if from.CookieManager == nil && to.CookieManager == nil {
					assert.Error(t, err)
					return
				}
				require.NoError(t, err)

				if from.CookieManager != nil {
					// URL found From value
					findURL, err := manager.FindURL(from.CookieManager.ToValue(servers[0].String()), servers)
					require.NoError(t, err)
					assert.Equal(t, servers[0], findURL)

					// URL not found From value
					findURL, _ = manager.FindURL(from.CookieManager.ToValue(servers[0].String()+"bar"), servers)
					assert.Nil(t, findURL)
				}

				if to.CookieManager != nil {
					// URL found To Value
					findURL, err := manager.FindURL(to.CookieManager.ToValue(servers[0].String()), servers)
					require.NoError(t, err)
					assert.Equal(t, servers[0], findURL)

					// URL not found To value
					findURL, _ = manager.FindURL(to.CookieManager.ToValue(servers[0].String()+"bar"), servers)
					assert.Nil(t, findURL)
				}
			})
		}
	}
}

func TestManager(t *testing.T) {

	servers := []*url.URL{
		{Scheme: "http", Host: "10.10.10.10", Path: "/"},
		{Scheme: "https", Host: "10.10.10.42", Path: "/"},
		{Scheme: "http", Host: "10.10.10.10", Path: "/foo"},
		{Scheme: "http", Host: "10.10.10.11", Path: "/", User: url.User("John Doe")},
	}

	hashManager := &HashValue{Salt: "foo"}
	defaultManager := &RawValue{}
	aesManager, err := NewAESManager([]byte("95Bx9JkKX3xbd7z3"), 5*time.Second)
	require.NoError(t, err)

	tests := []struct {
		name             string
		From             CookieValue
		To               CookieValue
		rawValue         string
		want             *url.URL
		expectError      bool
		expectErrorOnNew bool
	}{
		{
			name:     "From RawValue To HashValue with RawValue value",
			From:     defaultManager,
			To:       hashManager,
			rawValue: "http://10.10.10.10/",
			want:     servers[0],
		},
		{
			name:     "From RawValue To HashValue with RawValue non matching value",
			From:     defaultManager,
			To:       hashManager,
			rawValue: "http://24.10.10.10/",
		},
		{
			name:     "From RawValue To HashValue with HashValue value",
			From:     defaultManager,
			To:       hashManager,
			rawValue: hashManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name:     "From RawValue To HashValue with HashValue non matching value",
			From:     defaultManager,
			To:       hashManager,
			rawValue: hashManager.ToValue("http://24.10.10.10/"),
		},
		{
			name:     "From HashValue To AESValue with AESValue value",
			From:     hashManager,
			To:       aesManager,
			rawValue: aesManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name:     "From HashValue To AESValue with AESValue non matching value",
			From:     hashManager,
			To:       aesManager,
			rawValue: aesManager.ToValue("http://24.10.10.10/"),
		},
		{
			name:     "From HashValue To AESValue with HashValue value",
			From:     hashManager,
			To:       aesManager,
			rawValue: hashManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name:     "From HashValue To AESValue with AESValue non matching value",
			From:     hashManager,
			To:       aesManager,
			rawValue: aesManager.ToValue("http://24.10.10.10/"),
		},
		{
			name:     "From AESValue To AESValue with AESValue value",
			From:     aesManager,
			To:       aesManager,
			rawValue: aesManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name:     "From AESValue To AESValue with AESValue non matching value",
			From:     aesManager,
			To:       aesManager,
			rawValue: aesManager.ToValue("http://24.10.10.10/"),
		},
		{
			name:     "From nil To AESValue with AESValue with matching value",
			To:       aesManager,
			rawValue: aesManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name:     "From HashValue To nil with HashValue with matching value",
			From:     hashManager,
			rawValue: hashManager.ToValue("http://10.10.10.10/"),
			want:     servers[0],
		},
		{
			name:     "From nil To AESValue with AESValue non matching value",
			To:       aesManager,
			rawValue: aesManager.ToValue("http://24.10.10.10/"),
		},
		{
			name:     "From HashValue To nil with HashValue non matching value",
			From:     hashManager,
			rawValue: hashManager.ToValue("http://24.10.10.10/"),
		},
		{
			name:             "From nil To nil",
			expectErrorOnNew: true,
		},
		{
			name:     "From AESValue To HashValue with HashValue non matching value",
			From:     aesManager,
			To:       hashManager,
			rawValue: hashManager.ToValue("http://24.10.10.10/"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewMigrationManager(tt.From, tt.To)
			if tt.expectErrorOnNew {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			findURL, err := manager.FindURL(tt.rawValue, servers)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, findURL)
		})
	}
}
