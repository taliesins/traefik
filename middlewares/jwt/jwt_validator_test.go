package jwt

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/testhelpers"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/negroni"
	"gopkg.in/square/go-jose.v1"
	"os"
	"path"
	"reflect"
	"runtime"
	"net/url"
	"regexp"
	"strings"
)

const defaultAuthorizationHeaderName = "Authorization"
const idTokenQuerystringParameterName = "id_token"

type TokenMethod int

const (
	TokenMethodAuthorizationHeader TokenMethod = 1 + iota
	TokenMethodQuerystring
	TokenMethodCookie
)

func signHeaderWithClientSecret(req *http.Request, clientSecret string, claims *jwt.StandardClaims, tokenMethod TokenMethod) error {
	signingKey := []byte(clientSecret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return err
	}

	switch tokenMethod {
	case TokenMethodAuthorizationHeader:
		{
			req.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", signedToken))
		}
	case TokenMethodQuerystring:
		{
			q := req.URL.Query()
			q.Add(idTokenQuerystringParameterName, signedToken)
			req.URL.RawQuery = q.Encode()
		}
	case TokenMethodCookie:
		{
			cookie := &http.Cookie{
				Name:  sessionCookieName,
				Value: signedToken,
				//Path:"", //TODO: should we be validating the path?
				//Domain:"", //TODO: should we be validating the domain
			}
			req.AddCookie(cookie)
		}
	}

	return nil
}

func runMiddleWareWithClientSecretSigning(handlerFunc func(http.ResponseWriter, *http.Request), jwtConfiguration *types.Jwt, clientSecret string, claims *jwt.StandardClaims, tokenMethod TokenMethod, skipSigning bool, path string) (*http.Response, error) {
	jwtMiddleware, err := NewJwtValidator(jwtConfiguration, &tracing.Tracing{})
	if err != nil {
		return nil, err
	}

	handler := http.HandlerFunc(handlerFunc)
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}

	requestPath, err := url.Parse(path)
	base, err := url.Parse(ts.URL)
	requestUrl := base.ResolveReference(requestPath).String()

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl, nil)

	if !skipSigning {
		err = signHeaderWithClientSecret(req, clientSecret, claims, tokenMethod)
		if err != nil {
			return nil, err
		}
	}

	return client.Do(req)
}

func runTestWithClientSecretSuccess(t *testing.T, clientSecret string, tokenMethod TokenMethod) {
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	claims := &jwt.StandardClaims{}
	jwtConfiguration := &types.Jwt{
		ClientSecret: clientSecret,
	}

	res, err := runMiddleWareWithClientSecretSigning(handlerFunc, jwtConfiguration, clientSecret, claims, tokenMethod, false, "/")

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func runTestWithClientSecretFailure(t *testing.T, serverClientSecret string, clientClientSecret string, tokenMethod TokenMethod) {
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	claims := &jwt.StandardClaims{}
	jwtConfiguration := &types.Jwt{
		ClientSecret: serverClientSecret,
	}

	res, err := runMiddleWareWithClientSecretSigning(handlerFunc, jwtConfiguration, clientClientSecret, claims, tokenMethod, false, "/")

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, "traefik\n", string(body), "they should not be equal")
}

func signHeaderWithCertificate(req *http.Request, certificate *traefiktls.Certificate, signingMethod jwt.SigningMethod, kid string, claims *jwt.StandardClaims, tokenMethod TokenMethod) error {
	privateKeyPemData, err := certificate.KeyFile.Read()
	if err != nil {
		return err
	}

	privateKey, err := GetPrivateKeyFromPem(privateKeyPemData)
	if err != nil {
		return err
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return err
	}

	switch tokenMethod {
	case TokenMethodAuthorizationHeader:
		{
			req.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", signedToken))
		}
	case TokenMethodQuerystring:
		{
			q := req.URL.Query()
			q.Add(idTokenQuerystringParameterName, signedToken)
			req.URL.RawQuery = q.Encode()
		}
	case TokenMethodCookie:
		{
			cookie := &http.Cookie{
				Name:  sessionCookieName,
				Value: signedToken,
				//Path:"", //TODO: should we be validating the path?
				//Domain:"", //TODO: should we be validating the domain
			}
			req.AddCookie(cookie)
		}
	}

	return nil
}

func runMiddleWareWithCertificateSigning(handlerFunc func(http.ResponseWriter, *http.Request), jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, signingMethod jwt.SigningMethod, kid string, claims *jwt.StandardClaims, tokenMethod TokenMethod, skipSigning bool, path string) (*http.Response, error) {
	jwtMiddleware, err := NewJwtValidator(jwtConfiguration, &tracing.Tracing{})
	if err != nil {
		return nil, err
	}

	handler := http.HandlerFunc(handlerFunc)
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}

	requestPath, err := url.Parse(path)
	base, err := url.Parse(ts.URL)
	requestUrl := base.ResolveReference(requestPath).String()

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl, nil)
	if !skipSigning {
		err = signHeaderWithCertificate(req, certificate, signingMethod, kid, claims, tokenMethod)
		if err != nil {
			return nil, err
		}
	}

	return client.Do(req)
}

func runTestWithPublicKeySuccess(t *testing.T, signingMethod jwt.SigningMethod, certificatePath string, tokenMethod TokenMethod) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), certificatePath)

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil {
		panic(err)
	}
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	kid := ""
	claims := &jwt.StandardClaims{}
	jwtConfiguration := &types.Jwt{
		PublicKey: string(certContent),
	}

	res, err := runMiddleWareWithCertificateSigning(handlerFunc, jwtConfiguration, certificate, signingMethod, kid, claims, tokenMethod, false, "/")

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, "traefik\n", string(body), "they should be equal")
}

func runTestWithPublicKeyFailure(t *testing.T, signingMethod jwt.SigningMethod, publicKeyRootPath string, privateKeyRootPath string, tokenMethod TokenMethod) {
	_, filename, _, _ := runtime.Caller(0)

	publicKeyPath := fmt.Sprintf("%s.crt", path.Join(path.Dir(filename), publicKeyRootPath))
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", path.Join(path.Dir(filename), publicKeyRootPath))
	}

	privateKeyPath := fmt.Sprintf("%s.key", path.Join(path.Dir(filename), privateKeyRootPath))

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil {
		panic(err)
	}
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	kid := ""
	claims := &jwt.StandardClaims{}
	jwtConfiguration := &types.Jwt{
		PublicKey: string(certContent),
	}

	res, err := runMiddleWareWithCertificateSigning(handlerFunc, jwtConfiguration, certificate, signingMethod, kid, claims, tokenMethod, false, "/")

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, "traefik\n", string(body), "they should not be equal")
}

func getJsonWebset(certificate *traefiktls.Certificate) (*jose.JsonWebKeySet, error) {
	publicKeyPemData, err := certificate.CertFile.Read()
	if err != nil {
		return nil, err
	}

	publicKey, _, err := GetPublicKeyFromPem(publicKeyPemData)
	if err != nil {
		return nil, err
	}

	var algorithm string
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		algorithm = "RSA"
	case *ecdsa.PublicKey:
		algorithm = "EC"
	default:
		return nil, fmt.Errorf("unknown private key type '%s'", reflect.TypeOf(key))
	}

	jsonWebKeySet := &jose.JsonWebKeySet{
		Keys: []jose.JsonWebKey{
			{
				Key:       publicKey,
				KeyID:     "0",
				Use:       "sig",
				Algorithm: algorithm,
			},
		},
	}

	return jsonWebKeySet, nil
}

func runTestWithDiscoverySuccess(t *testing.T, signingMethod jwt.SigningMethod, certificatePath string, setIssuer bool, setOidcDiscoveryUri bool, setJwksUri bool, tokenMethod TokenMethod) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), certificatePath)

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if err != nil {
		panic(err)
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if err != nil {
		panic(err)
	}

	oidcDiscoveryUriPath := "/.well-known/openid-configuration"
	jwksUriPath := "/common/discovery/keys"

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.RequestURI == oidcDiscoveryUriPath {
			var scheme string
			if r.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
			jwksUri := fmt.Sprintf("%s://%s%s", scheme, r.Host, jwksUriPath)
			fmt.Fprintln(w, fmt.Sprintf(`{"jwks_uri":"%s"}`, jwksUri))
		} else if r.RequestURI == jwksUriPath {
			w.Write(jsonWebKeySetJson)
		} else {
			panic("Don't know how to handle request")
		}
	}))
	defer jwksServer.Close()

	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	kid := "0"
	claims := &jwt.StandardClaims{
		Issuer: jwksServer.URL,
	}
	jwtConfiguration := &types.Jwt{}
	if setIssuer {
		jwtConfiguration.Issuer = jwksServer.URL
	}
	if setOidcDiscoveryUri {
		jwtConfiguration.DiscoveryAddress = fmt.Sprintf("%s%s", jwksServer.URL, oidcDiscoveryUriPath)
	}
	if setJwksUri {
		jwtConfiguration.JwksAddress = fmt.Sprintf("%s%s", jwksServer.URL, jwksUriPath)
	}

	res, err := runMiddleWareWithCertificateSigning(handlerFunc, jwtConfiguration, certificate, signingMethod, kid, claims, tokenMethod, false, "/")

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, "traefik\n", string(body), "they should be equal")
}

func TestWithClientSecretInAuthorizationHeaderSuccess(t *testing.T) {
	runTestWithClientSecretSuccess(t, "mySecret", TokenMethodAuthorizationHeader)
}

func TestWithClientSecretInAuthorizationHeaderWrongSecretFailure(t *testing.T) {
	runTestWithClientSecretFailure(t, "mySecret", "mySecretWrong", TokenMethodAuthorizationHeader)
}

func TestWithClientSecretInQuerystringSuccess(t *testing.T) {
	runTestWithClientSecretSuccess(t, "mySecret", TokenMethodQuerystring)
}

func TestWithClientSecretInQuerystringWrongSecretFailure(t *testing.T) {
	runTestWithClientSecretFailure(t, "mySecret", "mySecretWrong", TokenMethodQuerystring)
}

func TestWithClientSecretInCookieSuccess(t *testing.T) {
	runTestWithClientSecretSuccess(t, "mySecret", TokenMethodCookie)
}

func TestWithClientSecretInCookieWrongSecretFailure(t *testing.T) {
	runTestWithClientSecretFailure(t, "mySecret", "mySecretWrong", TokenMethodCookie)
}

func TestWithPublicKeyInAuthorizationHeaderSuccess(t *testing.T) {
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES256, "signing/es256", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES384, "signing/es384", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES512, "signing/es512", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS256, "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS384, "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS512, "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS256, "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS384, "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS512, "signing/rsa", TokenMethodAuthorizationHeader)
}

func TestWithPublicKeyInAuthorizationHeaderFailure(t *testing.T) {
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES256, "../../integration/fixtures/https/snitest.com", "signing/es256", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES384, "../../integration/fixtures/https/snitest.com", "signing/es384", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES512, "../../integration/fixtures/https/snitest.com", "signing/es512", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS384, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS512, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS384, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS512, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
}

func TestWithPublicKeyInQuerystringSuccess(t *testing.T) {
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES256, "signing/es256", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES384, "signing/es384", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES512, "signing/es512", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS256, "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS384, "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS512, "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS256, "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS384, "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS512, "signing/rsa", TokenMethodQuerystring)
}

func TestWithPublicKeyInQuerystringFailure(t *testing.T) {
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES256, "../../integration/fixtures/https/snitest.com", "signing/es256", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES384, "../../integration/fixtures/https/snitest.com", "signing/es384", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES512, "../../integration/fixtures/https/snitest.com", "signing/es512", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS384, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS512, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS384, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS512, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodQuerystring)
}

func TestWithPublicKeyInCookieSuccess(t *testing.T) {
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES256, "signing/es256", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES384, "signing/es384", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodES512, "signing/es512", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS256, "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS384, "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodPS512, "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS256, "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS384, "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS512, "signing/rsa", TokenMethodCookie)
}

func TestWithPublicKeyInCookieFailure(t *testing.T) {
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES256, "../../integration/fixtures/https/snitest.com", "signing/es256", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES384, "../../integration/fixtures/https/snitest.com", "signing/es384", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES512, "../../integration/fixtures/https/snitest.com", "signing/es512", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS384, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS512, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS384, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS512, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodCookie)
}

func TestWithSignedRsaPublicKeySuccess(t *testing.T) {
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS256, "../../integration/fixtures/https/snitest.com", TokenMethodAuthorizationHeader)
}

func TestWithRsaPublicKeySignedWithWrongPrivateKeyFailure(t *testing.T) {
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
}

func TestWithRS256UsingJwksUriSuccess(t *testing.T) {
	runTestWithDiscoverySuccess(t, jwt.SigningMethodRS256, "signing/rsa", true, false, false, TokenMethodAuthorizationHeader)
}

func TestWithRS256UsingOpenIdConnectDiscoveryUriSuccess(t *testing.T) {
	runTestWithDiscoverySuccess(t, jwt.SigningMethodRS256, "signing/rsa", false, true, false, TokenMethodAuthorizationHeader)
}

func TestWithRS256UsingIssuerUriSuccess(t *testing.T) {
	runTestWithDiscoverySuccess(t, jwt.SigningMethodRS256, "signing/rsa", false, false, true, TokenMethodAuthorizationHeader)
}

func TestWithNoAuthenticationAndNoSsoProvidedFailure(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if err != nil {
		panic(err)
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if err != nil {
		panic(err)
	}

	oidcDiscoveryUriPath := "/.well-known/openid-configuration"
	jwksUriPath := "/common/discovery/keys"

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.RequestURI == oidcDiscoveryUriPath {
			jwksUri := fmt.Sprintf("http://%s%s", r.Host, jwksUriPath)
			fmt.Fprintln(w, fmt.Sprintf(`{"jwks_uri":"%s"}`, jwksUri))
		} else if r.RequestURI == jwksUriPath {
			w.Write(jsonWebKeySetJson)
		} else {
			panic("Don't know how to handle request")
		}
	}))
	defer jwksServer.Close()

	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	kid := "0"
	claims := &jwt.StandardClaims{
		Issuer: jwksServer.URL,
	}
	jwtConfiguration := &types.Jwt{}
	jwtConfiguration.Issuer = jwksServer.URL

	res, err := runMiddleWareWithCertificateSigning(handlerFunc, jwtConfiguration, certificate, jwt.SigningMethodRS256, kid, claims, TokenMethodCookie, true, "/")

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	expectedBody := "\n"
	assert.EqualValues(t, expectedBody, string(body), "they should be equal")
}

func TestWithNoAuthenticationAndSsoProvidedFailure(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if err != nil {
		panic(err)
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if err != nil {
		panic(err)
	}

	oidcDiscoveryUriPath := "/.well-known/openid-configuration"
	jwksUriPath := "/common/discovery/keys"

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.RequestURI == oidcDiscoveryUriPath {
			jwksUri := fmt.Sprintf("http://%s%s", r.Host, jwksUriPath)
			fmt.Fprintln(w, fmt.Sprintf(`{"jwks_uri":"%s"}`, jwksUri))
		} else if r.RequestURI == jwksUriPath {
			w.Write(jsonWebKeySetJson)
		} else {
			panic("Don't know how to handle request")
		}
	}))
	defer jwksServer.Close()

	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	kid := "0"
	claims := &jwt.StandardClaims{
		Issuer: jwksServer.URL,
	}
	jwtConfiguration := &types.Jwt{}
	jwtConfiguration.Issuer = jwksServer.URL
	jwtConfiguration.SsoAddressTemplate = "https://login.microsoftonline.com/traefik_k8s_test.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=1234f2b2-9fe3-1234-11a6-f123e76e3843&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login"
	jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

	res, err := runMiddleWareWithCertificateSigning(handlerFunc, jwtConfiguration, certificate, jwt.SigningMethodRS256, kid, claims, TokenMethodCookie, true, "/")

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)

	expectedRedirectUri, err := url.Parse(res.Request.URL.String())
	if err != nil {
		panic(err)
	}

	expectedRedirectUri.Path = callbackPath


	expectedBodyRegex, err := regexp.Compile("\n<!DOCTYPE html><html><head><title></title></head><body>\n\n<script>\nwindow.location.replace\\('(.*)'\\);\n</script>\nPlease sign in at <a href='(.*)'>(.*)</a>\n</body></html>\n\n")
	expectedBodyMatches := expectedBodyRegex.FindStringSubmatch(string(body))
	assert.Len(t, expectedBodyMatches, 4, "Expect 4 matches")
	bodyMatch := expectedBodyMatches[1]

	redirectUrlRegex := strings.Replace(strings.Replace(strings.Replace(strings.Replace(strings.Replace(jwtConfiguration.SsoAddressTemplate, "{{.CallbackUrl}}", "(.*)", -1), "{{.State}}", "(.*)", -1), "{{.Nonce}}", "(.*)", -1), "/", "\\/", -1), "?", "\\?", -1)
	expectedRedirectUrlRegex, err := regexp.Compile(redirectUrlRegex)
	expectedRedirectUrlMatches := expectedRedirectUrlRegex.FindStringSubmatch(bodyMatch)
	assert.Len(t, expectedRedirectUrlMatches, 4, "Expect 4 matches")
	nonceMatch := expectedRedirectUrlMatches[1]
	redirectUriMatch := expectedRedirectUrlMatches[2]
	stateMatch := expectedRedirectUrlMatches[3]

	assert.NotEqual(t, url.QueryEscape(""), nonceMatch, "nonce should be specified")
	assert.EqualValues(t, url.QueryEscape(expectedRedirectUri.String()), redirectUriMatch, "redirect_uri should be specified")
	assert.NotEqual(t, url.QueryEscape(""), stateMatch, "state should be specified")
}

func TestWithRedirectFromSsoButIdTokenIsStoredInBookmarkFailure(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if err != nil {
		panic(err)
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if err != nil {
		panic(err)
	}

	oidcDiscoveryUriPath := "/.well-known/openid-configuration"
	jwksUriPath := "/common/discovery/keys"

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.RequestURI == oidcDiscoveryUriPath {
			jwksUri := fmt.Sprintf("http://%s%s", r.Host, jwksUriPath)
			fmt.Fprintln(w, fmt.Sprintf(`{"jwks_uri":"%s"}`, jwksUri))
		} else if r.RequestURI == jwksUriPath {
			w.Write(jsonWebKeySetJson)
		} else {
			panic("Don't know how to handle request")
		}
	}))
	defer jwksServer.Close()

	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	}

	jwtConfiguration := &types.Jwt{}
	jwtConfiguration.Issuer = jwksServer.URL
	jwtConfiguration.SsoAddressTemplate = "https://login.microsoftonline.com/traefik_k8s_test.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=1234f2b2-9fe3-1234-11a6-f123e76e3843&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login"
	jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

	jwtMiddleware, err := NewJwtValidator(jwtConfiguration, &tracing.Tracing{})
	if err != nil {
		panic(err)
	}

	handler := http.HandlerFunc(handlerFunc)
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}

	clientRequestUrl, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)
	}

	if clientRequestUrl.Path == ""{
		clientRequestUrl.Path = "/"
	}

	clientRequestUrl.Scheme = "http"

	//Work out the url that the SSO would redirect back to
	redirectUrl := clientRequestUrl.String()
	expectedReturnUrl := fmt.Sprintf("%s://%s%s?%s=%s", clientRequestUrl.Scheme, clientRequestUrl.Host, callbackPath, redirectUriQuerystringParameterName, url.QueryEscape(redirectUrl))
	expectedRedirectorUrl := fmt.Sprintf("%s://%s%s", clientRequestUrl.Scheme, clientRequestUrl.Host, redirectorPath)

	req := testhelpers.MustNewRequest(http.MethodGet, expectedReturnUrl, nil)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)

	expectedBody := fmt.Sprintf("\n<!DOCTYPE html><html><head><title></title></head><body>\n<script>\nfunction getBookMarkParameterByName(name, url) {\n    if (!url) url = window.location.hash;\n    name = name.replace(/[\\[\\]]/g, \"\\\\$&\");\n    var regex = new RegExp(\"[#&?]\" + name + \"(=([^&#]*)|&|#|$)\"), results = regex.exec(url);\n    if (!results) return null;\n    if (!results[2]) return '';\n    return decodeURIComponent(results[2].replace(/\\+/g, \" \"));\n}\n\nstate = getBookMarkParameterByName('state');\nif (state) {\n\tdocument.cookie = 'id_token=' + getBookMarkParameterByName('id_token');\n\twindow.location.replace('%s?' + state);\n}\n</script>\nPlease change the '#' in the url to '&' and goto link\n</body></html>\n\n", expectedRedirectorUrl)

	assert.EqualValues(t, expectedBody, string(body), "they should be equal")
}
