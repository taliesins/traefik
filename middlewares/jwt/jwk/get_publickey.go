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

type wellKnownOpenIdConfigurationCacheValue struct {
	JwksUri string
}

type jwksCacheValue struct {
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

func GetJwksUri(issuer string) (jwksUri string, err error) {
	wellKnownOpenIdConfigurationUri := fmt.Sprintf("%s.well-known/openid-configuration", issuer)

	// Try to get and return existing entry from cache. If cache is expired,
	// it will try proceed with rest of the function call
	cached, ok := lruCache.Get(wellKnownOpenIdConfigurationUri)
	if ok {
		jwksUri := cached.(*wellKnownOpenIdConfigurationCacheValue).JwksUri
		return jwksUri, nil
	}

	resp, err := http.Get(wellKnownOpenIdConfigurationUri)
	if err != nil {
		return "", fmt.Errorf("json validation error: %s", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("json validation error: %s", err)
	}
	defer resp.Body.Close()

	data := make(map[string]interface{})
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}

	jwksUri, ok = data["jwks_uri"].(string)

	if !ok {
		return "", fmt.Errorf("json does not contain jwks_uri: %s", err)
	}

	lruCache.Add(wellKnownOpenIdConfigurationUri, &wellKnownOpenIdConfigurationCacheValue{
		JwksUri: jwksUri,
	})

	return jwksUri, nil
}

// GetPublicKey verifies the desired iss and aud against the token's claims, and then
// tries to fetch a public key from the iss. It returns the public key as byte slice
// on success and error on failure.
func GetJwksPublicKey(token *jwt.Token, issuer, jwksUri string) ([]byte, error) {
	claims := token.Claims.(jwt.MapClaims)

	cacheKey := fmt.Sprintf("%s|%s", token.Header["kid"].(string), claims["iss"].(string))

	// Try to get and return existing entry from cache. If cache is expired,
	// it will try proceed with rest of the function call
	cached, ok := lruCache.Get(cacheKey)
	if ok {
		val := cached.(*jwksCacheValue)

		// Check for alg
		if val.Algorithm != token.Header["alg"] {
			return nil, fmt.Errorf("mismatch in token and JWKS algorithms")
		}

		// Check for expiry
		if time.Now().Before(cached.(*jwksCacheValue).Expiry) {
			cert := cached.(*jwksCacheValue)
			return cert.Data, nil
		}
	}

	if jwksUri == "" {
		newJwksUri, err := GetJwksUri(issuer)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve jwks uri: %s", err)
		}
		jwksUri = newJwksUri
	}

	resp, err := http.Get(jwksUri)
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
	lruCache.Add(cacheKey, &jwksCacheValue{
		Algorithm: alg,
		Data:      decoded,
		Expiry:    time.Unix(exp, 0),
	})

	return decoded, nil
}

func GetPublicKeyFile(token *jwt.Token, certFile string) ([]byte, error) {

	// Try to get and return existing entry from cache. If cache is expired,
	// it will try proceed with rest of the function call
	cached, ok := lruCache.Get(certFile)
	if ok {
		val := cached.(*jwksCacheValue)

		// Check for alg
		if val.Algorithm != token.Header["alg"] {
			return nil, fmt.Errorf("mismatch in token and expected algorithm")
		}

		// Check for expiry
		if time.Now().Before(cached.(*jwksCacheValue).Expiry) {
			cert := cached.(*jwksCacheValue)
			return cert.Data, nil
		}
	}

	pemData, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}

	block, rest := pem.Decode(pemData)
	if block == nil || len(rest) > 0 {
		log.Fatal("Certificate decoding error")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	cert_alg := cert.SignatureAlgorithm.String()

	alg := ""
	switch cert_alg {
	case "SHA1WithRSA":
		alg = "RS"
	case "SHA256WithRSA":
		alg = "RS256"
	case "SHA384WithRSA":
		alg = "RS384"
	case "SHA512WithRSA":
		alg = "RS512"

	case "SHA256WithRSAPSS":
		alg = "PS256"
	case "SHA384WithRSAPSS":
		alg = "PS384"
	case "SHA512WithRSAPSS":
		alg = "PS512"

	case "ECDSAWithSHA1":
		alg = "ES"
	case "ECDSAWithSHA256":
		alg = "ES256"
	case "ECDSAWithSHA384":
		alg = "ES384"
	case "ECDSAWithSHA512":
		alg = "ES512"

	case "DSAWithSHA1":
		alg = "DS"
	case "DSAWithSHA256":
		alg = "DS256"

	case "MD2WithRSA":
		alg = "MD2"
	case "MD5WithRSA":
		alg = "MD5"
	default:
		return nil, fmt.Errorf("Cert with signing type of %s cannot be used", cert_alg)
	}

	if alg != token.Header["alg"] {
		return nil, fmt.Errorf("mismatch in token and expected algorithm")
	}

	// Store value in cache
	lruCache.Add(certFile, &jwksCacheValue{
		Algorithm: alg,
		Data:      pemData,
		Expiry:    time.Now().Add(time.Minute * time.Duration(5)),
	})

	return pemData, nil
}
