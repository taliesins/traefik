package jwks

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/golang-lru"
	"gopkg.in/square/go-jose.v1"
)

var lruCache *lru.Cache

type cacheValue struct {
	Algorithm string
	Data      []byte
	Expiry    time.Time
}

func init() {
	l, err := lru.New(128)
	if err != nil {
		log.Fatal("Cannot initialize cache")
	}
	lruCache = l
}

// GetPublicKey verifies the desired iss and aud against the token's claims, and then
// tries to fetch a public key from the iss. It returns the public key as byte slice
// on success and error on failure.
func GetPublicKey(token *jwt.Token, iss, aud string) ([]byte, error) {
	claims := token.Claims.(jwt.MapClaims)

	// Get iss from JWT and validate against desired iss
	if claims["iss"].(string) != iss {
		return nil, fmt.Errorf("cannot validate iss claim")
	}

	// Get audience from JWT and validate against desired audience
	if claims["aud"].(string) != aud {
		return nil, fmt.Errorf("Cannot validate audience claim")
	}

	cacheKey := fmt.Sprintf("%s|%s", token.Header["kid"].(string), claims["iss"].(string))

	// Try to get and return existing entry from cache. If cache is expired,
	// it will try proceed with rest of the function call
	cached, ok := lruCache.Get(cacheKey)
	if ok {
		val := cached.(*cacheValue)

		// Check for alg
		if val.Algorithm != token.Header["alg"] {
			return nil, fmt.Errorf("mismatch in token and JWKS algorithms")
		}

		// Check for expiry
		if time.Now().Before(cached.(*cacheValue).Expiry) {
			cert := cached.(*cacheValue)
			return cert.Data, nil
		}
	}

	url := fmt.Sprintf("%s.well-known/jwks.json", iss)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("json validation error: %s", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("json validation error: %s", err)
	}
	defer resp.Body.Close()

	jwks := &jose.JsonWebKeySet{}
	err = json.Unmarshal(body, jwks)
	if err != nil {
		return nil, fmt.Errorf("json validation error c: %s", err)
	}

	// Get desired key from JWKS
	kid := token.Header["kid"].(string)
	key := jwks.Key(kid)[0]
	if !key.Valid() {
		return nil, fmt.Errorf("invalid JWKS key")
	}

	// Check for alg
	alg := key.Algorithm
	if alg != token.Header["alg"] {
		return nil, fmt.Errorf("mismatch in token and JWKS algorithms")
	}

	pk := key.Certificates[0].PublicKey
	pemData, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, fmt.Errorf("json validation error: %s", err)
	}

	buf := new(bytes.Buffer)
	pem.Encode(buf, &pem.Block{Type: "PUBLIC KEY", Bytes: pemData})
	decoded := buf.Bytes()

	// Store value in cache
	exp := claims["exp"].(int64)
	lruCache.Add(cacheKey, &cacheValue{
		Algorithm: alg,
		Data:      decoded,
		Expiry:    time.Unix(exp, 0),
	})

	return decoded, nil
}
