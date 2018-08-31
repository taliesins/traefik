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
	"gopkg.in/square/go-jose.v2"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/dgrijalva/jwt-go"
	"net/url"
	"crypto/tls"
	"crypto/rsa"
	"crypto/ecdsa"
)

var lruCache *lru.Cache

type openIdConnectDiscoveryCacheValue struct {
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

func DownloadOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri string)(string, error){
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(openIdConnectDiscoveryUri)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data := make(map[string]interface{})
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}

	jwksUri, ok := data["jwks_uri"].(string)

	if !ok {
		return "", fmt.Errorf("json does not contain jwks_uri: %s", err)
	}

	return jwksUri, nil
}

func GetJwksUriFromOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri string) (jwksUri string, err error) {
	// Try to get and return existing entry from cache. If cache is expired,
	// it will try proceed with rest of the function call
	cached, ok := lruCache.Get(openIdConnectDiscoveryUri)
	if ok {
		jwksUri = cached.(*openIdConnectDiscoveryCacheValue).JwksUri
		return jwksUri, nil
	}

	jwksUri, err = DownloadOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri)

	if err != nil {
		return "", err
	}

	lruCache.Add(openIdConnectDiscoveryUri, &openIdConnectDiscoveryCacheValue{
		JwksUri: jwksUri,
	})

	return jwksUri, nil
}

func GetPublicKeyFromOpenIdConnectDiscoveryUri(kid string, openIdConnectDiscoveryUri string) (interface{}, x509.SignatureAlgorithm, error) {
	explicitJwksUri, err := GetJwksUriFromOpenIdConnectDiscoveryUri(openIdConnectDiscoveryUri)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unable to retrieve jwks uri: %s", err)
	}

	return GetPublicKeyFromJwksUri(kid, explicitJwksUri)
}

func GetPublicKeyFromIssuerUri(kid string, issuerUri string) (interface{}, x509.SignatureAlgorithm, error) {
	wellKnownUri, err := url.Parse(".well-known/openid-configuration")
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	openIdConnectDiscoveryUri, err := url.Parse(issuerUri)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	openIdConnectDiscoveryUri = openIdConnectDiscoveryUri.ResolveReference(wellKnownUri)

	return GetPublicKeyFromOpenIdConnectDiscoveryUri(kid, openIdConnectDiscoveryUri.String())
}

func DownloadJwksUri(jwksUri string)(*jose.JSONWebKeySet, error){
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(jwksUri)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	jwks := &jose.JSONWebKeySet{}
	err = json.Unmarshal(body, jwks)
	if err != nil {
		return nil, err
	}

	return jwks, nil
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

	jwks, err := DownloadJwksUri(jwksUri)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	publicKey, signingAlgorithm, err := GetPublicKeyFromJwks(jwks, kid)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	lruCache.Add(cacheKey, &jwksCacheValue{
		SigningAlgorithm: signingAlgorithm,
		Data:             publicKey,
		Expiry:           time.Now().Add(time.Minute * time.Duration(5)),
	})

	return publicKey, signingAlgorithm, nil
}

func GetPrivateKeyFromFileOrContent(certificateFileOrContents string) (interface{}, x509.SignatureAlgorithm, error) {
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

	privateKey, err := GetPrivateKeyFromPem(pemData)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, err
	}

	// Store value in cache
	lruCache.Add(certificateFileOrContents, &jwksCacheValue{
		SigningAlgorithm: x509.UnknownSignatureAlgorithm,
		Data:             privateKey,
		Expiry:           time.Now().Add(time.Minute * time.Duration(5)),
	})

	return privateKey, x509.UnknownSignatureAlgorithm, nil
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

func GetPublicKeyFromJwks(jwks *jose.JSONWebKeySet, kid string) (interface{}, x509.SignatureAlgorithm, error) {
	for _, key := range jwks.Keys {
		if key.KeyID == kid {
			if !key.Valid() {
				return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("invalid JWKS key")
			}
			if len(key.Certificates) > 0 {
				return key.Key, key.Certificates[0].SignatureAlgorithm, nil
			} else {
				return key.Key, x509.UnknownSignatureAlgorithm, nil
			}
		}
	}

	jwksJson, _ := json.Marshal(jwks)
	return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("JsonWebKeySet does not contain key: kid=%s jwks=%s", kid, jwksJson)
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

func SignMac(signingString string, key interface{}) (string, error){
	switch privateKeyType := key.(type) {
	case *rsa.PrivateKey:
		{
			return jwt.SigningMethodRS256.Sign(signingString, privateKeyType)

		}
	case *ecdsa.PrivateKey:
		{
			return jwt.SigningMethodES256.Sign(signingString, privateKeyType)
		}
	case []byte:
		{
			return jwt.SigningMethodHS256.Sign(signingString, key)
		}
	default:
		return "", fmt.Errorf("Unsupported key type %T", privateKeyType)
	}
}

func VerifyMac(signingString string, signature string, key interface{}) (error){
	switch publicKeyType := key.(type) {
	case *rsa.PrivateKey:
		{
			return jwt.SigningMethodRS256.Verify(signingString, signature, &publicKeyType.PublicKey)

		}
	case *ecdsa.PrivateKey:
		{
			return jwt.SigningMethodES256.Verify(signingString, signature, &publicKeyType.PublicKey)
		}
	case *rsa.PublicKey:
		{
			return jwt.SigningMethodRS256.Verify(signingString, signature, publicKeyType)

		}
	case *ecdsa.PublicKey:
		{
			return jwt.SigningMethodES256.Verify(signingString, signature, publicKeyType)
		}
	case []byte:
		{
			return jwt.SigningMethodHS256.Verify(signingString, signature, key)
		}
	default:
		return fmt.Errorf("Unsupported key type %T", publicKeyType)
	}
}