package stickycookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrorOut = log.New(ioutil.Discard, "[ERROR] ", 0)

// AESManager manage hashed sticky value.
type AESManager struct {
	block cipher.AEAD
	ttl   time.Duration
}

// NewAESManager takes a fixed-size key and returns an Manager or an error.
// Key size must be exactly one of 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewAESManager(key []byte, ttl time.Duration) (*AESManager, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESManager{
		block: aesgcm,
		ttl:   ttl,
	}, nil
}

// ToValue hashes the sticky value.
func (am *AESManager) ToValue(raw string) string {
	if am.ttl > 0 {
		raw = fmt.Sprintf("%s|%d", raw, time.Now().UTC().Add(am.ttl).Unix())
	}

	/*
		Nonce is the 64bit nanosecond-resolution time, plus 32bits of crypto/rand, for 96bits (12Bytes).
		Theoretically, if 2^32 calls were made in 1 nanosecon, there might be a repeat.
		Adds ~765ns, and 4B heap in 1 alloc (Benchmark_NonceTimeRandom4 below)

		Benchmark_NonceRandom12-8      	 2000000	       723 ns/op	      16 B/op	       1 allocs/op
		Benchmark_NonceRandom4-8       	 2000000	       698 ns/op	       4 B/op	       1 allocs/op
		Benchmark_NonceTimeRandom4-8   	 2000000	       765 ns/op	       4 B/op	       1 allocs/op
	*/
	nonce := make([]byte, 12)
	binary.PutVarint(nonce, time.Now().UnixNano())
	rpend := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, rpend); err != nil {
		// This is a near-impossible error condition on Linux systems.
		// An error here means rand.Reader (and thus getrandom(2), and thus /dev/urandom) returned
		// less than 4 bytes of data. /dev/urandom is guaranteed to always return the number of
		// bytes requested up to 512 bytes on modern kernels. Behaviour on non-Linux systems
		// varies, of course.
		panic(err)
	}
	for i := 0; i < 4; i++ {
		nonce[i+8] = rpend[i]
	}

	obfuscated := am.block.Seal(nil, nonce, []byte(raw), nil)
	// We append the 12byte nonce onto the end of the message
	obfuscated = append(obfuscated, nonce...)
	obfuscatedStr := base64.RawURLEncoding.EncodeToString(obfuscated)
	return obfuscatedStr
}

func (am *AESManager) Normalized2(obfuscatedStr string) string {
	obfuscated, err := base64.RawURLEncoding.DecodeString(obfuscatedStr)
	if err != nil {
		ErrorOut.Printf("AesManager.Normalize Decoding base64 failed with '%s'\n", err)
		return ""
	}

	// The first len-12 bytes is the ciphertext, the last 12 bytes is the nonce
	n := len(obfuscated) - 12
	if n <= 0 {
		// Protect against range errors causing panics
		ErrorOut.Printf("AesManager.Normalize post-base64-decoded string is too short\n")
		return ""
	}

	nonce := obfuscated[n:]
	obfuscated = obfuscated[:n]

	raw, err := am.block.Open(nil, nonce, []byte(obfuscated), nil)
	if err != nil {
		// um....
		ErrorOut.Printf("AesManager.Normalize Open failed with '%s'\n", err)
		return ""
	}
	if am.ttl > 0 {
		rawparts := strings.Split(string(raw), "|")
		if len(rawparts) < 2 {
			ErrorOut.Printf("AesManager.Normalize TTL set but cookie doesn't contain an expiration: '%s'\n", raw)
			return ""
		}
		// validate the ttl
		i, err := strconv.ParseInt(rawparts[1], 10, 64)
		if err != nil {
			ErrorOut.Printf("AesManager.Normalize TTL can't be parsed: '%s'\n", raw)
			return ""
		}
		if time.Now().UTC().After(time.Unix(i, 0).UTC()) {
			strTime := time.Unix(i, 0).UTC().String()
			ErrorOut.Printf("AesManager.Normalize TTL expired: '%s' (%s)\n", raw, strTime)
			return ""
		}
		raw = []byte(rawparts[0])
	}

	return string(raw)
}

// FindURL get url from array that match the value.
func (am *AESManager) FindURL(raw string, urls []*url.URL) *url.URL {
	rawURL := am.Normalized2(raw)
	for _, u := range urls {
		if areEqual(rawURL, u) {
			return u
		}
	}

	return nil
}
