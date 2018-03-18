package jwt

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"github.com/hashicorp/golang-lru"
	"gopkg.in/square/go-jose.v1"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/dgrijalva/jwt-go"
)

var lruCache *lru.Cache

type wellKnownOpenIdConfigurationCacheValue struct {
	JwksUri string
}

type jwksCacheValue struct {
	SigningAlgorithm x509.SignatureAlgorithm
	Data             interface{}
	Expiry           time.Time
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

func GetPublicKeyFromWellKnownUri(kid string, expectedIssuer string) (interface{}, x509.SignatureAlgorithm, error) {
	explicitJwksUri, err := GetJwksUri(expectedIssuer)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unable to retrieve jwks uri: %s", err)
	}

	return GetPublicKeyFromJwksUri(kid, explicitJwksUri)
}

func GetPublicKeyFromJwksUri(kid string, jwksUri string) (interface{}, x509.SignatureAlgorithm, error) {
	cacheKey := fmt.Sprintf("%s|%s", jwksUri, kid)

	// Try to get and return existing entry from cache. If cache is expired,
	// it will try proceed with rest of the function call
	cached, ok := lruCache.Get(cacheKey)
	if ok {
		val := cached.(*jwksCacheValue)

		// Check for expiry
		if time.Now().Before(cached.(*jwksCacheValue).Expiry) {
			cert := cached.(*jwksCacheValue)
			return cert.Data, val.SigningAlgorithm, nil
		}
	}

	resp, err := http.Get(jwksUri)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}
	defer resp.Body.Close()

	jwks := &jose.JsonWebKeySet{}
	err = json.Unmarshal(body, jwks)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	publicKey, signingAlgorithm, err := GetPublicKeyFromJsonWebKeySet(jwks, kid)

	lruCache.Add(cacheKey, &jwksCacheValue{
		SigningAlgorithm: signingAlgorithm,
		Data:             publicKey,
		Expiry:           time.Now().Add(time.Minute * time.Duration(5)),
	})

	return publicKey, signingAlgorithm, nil
}

func GetPrivateKeyFromPem(privateKeyPemData []byte) (interface{}, error){
	privateKeyBlock, rest := pem.Decode(privateKeyPemData)
	if privateKeyBlock == nil || len(rest) > 0 {
		return nil, fmt.Errorf("Private key decoding error")
	}

	switch privateKeyBlock.Type {
	case "RSA PRIVATE KEY":
		return jwt.ParseRSAPrivateKeyFromPEM(privateKeyPemData)
	case "EC PRIVATE KEY":
		return jwt.ParseECPrivateKeyFromPEM(privateKeyPemData)
	default:
		return nil, fmt.Errorf("Unsupported private key type %q", privateKeyBlock.Type)
	}
}


func GetPublicKeyFromJsonWebKeySet(jwks *jose.JsonWebKeySet, kid string) (interface{}, x509.SignatureAlgorithm, error) {
	key := jwks.Key(kid)[0]
	if !key.Valid() {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("invalid JWKS key")
	}

	if len(key.Certificates) > 0 {
		return key.Key, key.Certificates[0].SignatureAlgorithm, nil
	} else {
		return key.Key, x509.UnknownSignatureAlgorithm, nil
	}
}

func GetPublicKeyFromPem(publicKeyPemData []byte) (interface{}, x509.SignatureAlgorithm, error){
	publicKeyBlock, rest := pem.Decode(publicKeyPemData)
	if publicKeyBlock == nil || len(rest) > 0 {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("Certificate decoding error")
	}

	switch publicKeyBlock.Type {
	case "CERTIFICATE":
		{
			cert, err := x509.ParseCertificate(publicKeyBlock.Bytes)
			if err != nil {
				return nil, x509.UnknownSignatureAlgorithm, err
			}

			return cert.PublicKey, cert.SignatureAlgorithm, nil
		}
	case "PUBLIC KEY":
		{
			publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
			if err != nil {
				return nil, x509.UnknownSignatureAlgorithm, err
			}

			return publicKey, x509.UnknownSignatureAlgorithm, nil
		}
	}

	return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("Unsupported public key type %q", publicKeyBlock.Type)
}

func GetPublicKeyFromFileOrContent(certificateFileOrContents string) (interface{}, x509.SignatureAlgorithm, error) {
	// Try to get and return existing entry from cache. If cache is expired,
	// it will try proceed with rest of the function call
	cached, ok := lruCache.Get(certificateFileOrContents)
	if ok {
		val := cached.(*jwksCacheValue)

		// Check for expiry
		if time.Now().Before(cached.(*jwksCacheValue).Expiry) {
			cert := cached.(*jwksCacheValue)
			return cert.Data, val.SigningAlgorithm, nil
		}
	}

	pemData, err := traefiktls.FileOrContent(certificateFileOrContents).Read()
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	publicKey, signingAlgorithm, err := GetPublicKeyFromPem(pemData)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	// Store value in cache
	lruCache.Add(certificateFileOrContents, &jwksCacheValue{
		SigningAlgorithm: signingAlgorithm,
		Data:             publicKey,
		Expiry:           time.Now().Add(time.Minute * time.Duration(5)),
	})

	return publicKey, signingAlgorithm, nil
}