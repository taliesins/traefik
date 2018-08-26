package jwt

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"encoding/json"
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/testhelpers"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/negroni"
	"os"
	"path"
	"runtime"
	"net/url"
	"regexp"
	"strings"
	"time"
	"strconv"
	"github.com/containous/traefik/server/uuid"
	"crypto/tls"
	"reflect"
	"gopkg.in/square/go-jose.v2"
	"crypto/rsa"
	"crypto/ecdsa"
)

const defaultAuthorizationHeaderName = "Authorization"
const idTokenQuerystringParameterName = "id_token"

type TokenMethod int

const (
	TokenMethodAuthorizationHeader TokenMethod = 1 + iota
	TokenMethodQuerystring
	TokenMethodCookie
)

func templateToRegexFixer(template string)(string){
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		//".", "\\.", // will break {{.Url}}
		//"{", "\\{", // will break {{.Url}}
		"/", "\\/",
		"^", "\\^",
		"$", "\\$",
		"*", "\\*",
		"+", "\\+",
		"?", "\\?",
		"(", "\\(",
		")", "\\)",
		"[", "\\[",
		"|", "\\|",
	)

	return replacer.Replace(template)
}

func getCertificateFromPath(publicKeyRootPath string, privateKeyRootPath string)(*traefiktls.Certificate, error){
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
		return nil, fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile))
	}

	if !certificate.KeyFile.IsPath() {
		return nil, fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile))
	}

	return certificate, nil
}

func addTokenToRequest(req *http.Request, tokenMethod TokenMethod, signedToken string){
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
			}
			req.AddCookie(cookie)
		}
	}
}

func getJsonWebset(certificate *traefiktls.Certificate) (*jose.JSONWebKeySet, error) {
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

	jsonWebKeySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
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

func getMiddlewareServer(jwtConfiguration *types.Jwt)(server *httptest.Server, err error){
	jwtMiddleware, err := NewJwtValidator(jwtConfiguration, &tracing.Tracing{})
	if err != nil {
		return nil, err
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf(`{"RequestUri":"%s", "Referer":"%s"}`, r.URL.String(), r.Referer() ))
	})

	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	middlewareServer := httptest.NewTLSServer(n)

	return middlewareServer, nil
}

type overrideJwtConfiguration func(jwtConfig *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt)

func buildTestServers(publicKeyRootPath string, privateKeyRootPath string, overrideJwtConfiguration overrideJwtConfiguration) (certificate *traefiktls.Certificate, jwksServer *httptest.Server, middlwareServer *httptest.Server, err error) {
	if publicKeyRootPath == "" {
		publicKeyRootPath = "signing/rsa"
	}

	if privateKeyRootPath == "" {
		privateKeyRootPath = "signing/rsa"
	}

	certificate, err = getCertificateFromPath(publicKeyRootPath, privateKeyRootPath)
	if err != nil {
		return nil, nil, nil, err
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if err != nil {
		return nil, nil, nil, err
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if err != nil {
		return nil, nil, nil, err
	}

	oidcDiscoveryUriPath := "/.well-known/openid-configuration"
	jwksUriPath := "/common/discovery/keys"

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.RequestURI == oidcDiscoveryUriPath {
			jwksUri := fmt.Sprintf("https://%s%s", r.Host, jwksUriPath)
			fmt.Fprintln(w, fmt.Sprintf(`{"jwks_uri":"%s"}`, jwksUri))
		} else if r.RequestURI == jwksUriPath {
			w.Write(jsonWebKeySetJson)
		} else {
			panic("Don't know how to handle request")
		}
	}))

	ssoAddressTemplate := "https://login.microsoftonline.com/traefik_k8s_test.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=1234f2b2-9fe3-1234-11a6-f123e76e3843&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login"
	issuerUri, err := url.Parse(jwksServer.URL)
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	oidcDiscoveryUri, err := url.Parse(fmt.Sprintf("%s%s", jwksServer.URL, oidcDiscoveryUriPath))
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	jwksUri, err := url.Parse(fmt.Sprintf("%s%s", jwksServer.URL, jwksUriPath))
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	jwtConfiguration := &types.Jwt{}
	if overrideJwtConfiguration != nil {
		overrideJwtConfiguration(jwtConfiguration, certificate, ssoAddressTemplate, issuerUri, oidcDiscoveryUri, jwksUri)
	} else {
		jwtConfiguration.DiscoveryAddress = oidcDiscoveryUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()
	}

	middlewareServer, err := getMiddlewareServer(jwtConfiguration)
	if err != nil {
		jwksServer.Close()
		return nil, nil, nil, err
	}

	return certificate, jwksServer, middlewareServer, nil
}

type overrideClient func(*http.Client) (*http.Client)

type overrideClaims func(claims *jwt.StandardClaims, certificate *traefiktls.Certificate, jwksServer *httptest.Server, middlwareServer *httptest.Server) (*jwt.StandardClaims)

type overrideToken func(*jwt.Token)

func buildTestClient(certificate *traefiktls.Certificate, clientSecret string, jwksServer *httptest.Server, middlwareServer *httptest.Server, tokenSigningMethod jwt.SigningMethod, requestPath string, overrideClient overrideClient, overrideClaims overrideClaims, overrideToken overrideToken) (client *http.Client, nonce string, issuedAt string, signedToken string, clientRequestUrl *url.URL, expectedRedirectorUrl *url.URL, err error) {
	client = &http.Client{}
	if overrideClient != nil {
		overrideClient(client)
	} else {
		client.Transport= &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.CheckRedirect= func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if requestPath == "" {
		requestPath = "/"
	}
	clientRequestPath, err := url.Parse(requestPath)
	base, err := url.Parse(middlwareServer.URL)
	clientRequestUrl = base.ResolveReference(clientRequestPath)

	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	nonce = uuid.Get()
	issuedAt = strconv.FormatInt(time.Now().UTC().UnixNano(), 10)

	//Work out the url that the SSO would redirect back to
	expectedRedirectorUrl, err = url.Parse(fmt.Sprintf("%s://%s%s?iat=%s&nonce=%s&redirect_uri=%s", clientRequestUrl.Scheme, clientRequestUrl.Host, redirectorPath, issuedAt, nonce, url.QueryEscape(clientRequestUrl.String())))
	if err != nil {
		return nil, "", "", "", nil, nil, err
	}

	var privateKey interface{}
	if clientSecret != ""  {
		if tokenSigningMethod != jwt.SigningMethodHS256 && tokenSigningMethod != jwt.SigningMethodHS384 && tokenSigningMethod != jwt.SigningMethodHS512 {
			return nil, "", "", "", nil, nil, fmt.Errorf("certificate needs to be specified with this signing method")
		}

		privateKey = []byte(clientSecret)
	} else if certificate != nil {
		if tokenSigningMethod == jwt.SigningMethodHS256 || tokenSigningMethod == jwt.SigningMethodHS384 || tokenSigningMethod == jwt.SigningMethodHS512 {
			return nil, "", "", "", nil, nil, fmt.Errorf("client secret needs to be specified with this signing method")
		}

		//Need the signing key to use for mac of url, so just use the one we use for JWT
		privateKeyPemData, err := certificate.KeyFile.Read()
		if err != nil {
			return nil, "", "", "", nil, nil, err
		}

		privateKey, err = GetPrivateKeyFromPem(privateKeyPemData)
		if err != nil {
			return nil, "", "", "", nil, nil, err
		}
	} else {
		return nil, "", "", "", nil, nil, fmt.Errorf("certificate and client secret not specified, there is no way to sign request")
	}

	addMacHashToUrl(expectedRedirectorUrl, privateKey)

	claims := &jwt.StandardClaims{}
	if overrideClaims != nil {
		overrideClaims(claims, certificate, jwksServer, middlwareServer)
	} else {
		claims.Issuer = jwksServer.URL
	}

	token := jwt.NewWithClaims(tokenSigningMethod, claims)
	if overrideToken != nil {
		overrideToken(token)
	} else {
		token.Header["kid"] = "0"
	}

	signedToken, err = token.SignedString(privateKey)
	if err != nil {
		return nil, "", "", "", nil,nil, err
	}

	return client, nonce, issuedAt, signedToken, clientRequestUrl, expectedRedirectorUrl, nil
}

func runTestWithClientSecretSuccess(t *testing.T, clientSecret string, tokenMethod TokenMethod) {
	_, jwksServer, middlwareServer, err := buildTestServers("", "", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.ClientSecret=clientSecret
		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, requestUrl, _, err := buildTestClient(nil, clientSecret, jwksServer, middlwareServer, jwt.SigningMethodHS256, "", nil, nil, func(token *jwt.Token) {})

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	addTokenToRequest(req, tokenMethod, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Regexp(t, `{"RequestUri":"\/.*", "Referer":""}\n`, string(body), "they should be equal")
}

func runTestWithClientSecretFailure(t *testing.T, serverClientSecret string, clientClientSecret string, tokenMethod TokenMethod) {
	_, jwksServer, middlwareServer, err := buildTestServers("", "", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.ClientSecret=serverClientSecret
		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, requestUrl, _, err := buildTestClient(nil, clientClientSecret, jwksServer, middlwareServer, jwt.SigningMethodHS256, "", nil, nil, func(token *jwt.Token) {})

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	addTokenToRequest(req, tokenMethod, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}` + "\n", string(body), "they should not be equal")
}

func runTestWithPublicKeySuccess(t *testing.T, signingMethod jwt.SigningMethod, certificatePath string, tokenMethod TokenMethod) {
	certificate, jwksServer, middlwareServer, err := buildTestServers(certificatePath, certificatePath, func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		certContent, err := certificate.CertFile.Read()
		if err != nil {
			panic(err)
		}

		jwtConfiguration.PublicKey=string(certContent)

		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, requestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, signingMethod, "", nil, nil, nil)

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	addTokenToRequest(req, tokenMethod, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Regexp(t, `{"RequestUri":"\/.*", "Referer":""}\n`, string(body), "they should be equal")
}

func runTestWithPublicKeyFailure(t *testing.T, signingMethod jwt.SigningMethod, publicKeyRootPath string, privateKeyRootPath string, tokenMethod TokenMethod) {
	certificate, jwksServer, middlwareServer, err := buildTestServers(publicKeyRootPath, privateKeyRootPath, func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		certContent, err := certificate.CertFile.Read()
		if err != nil {
			panic(err)
		}

		jwtConfiguration.PublicKey=string(certContent)

		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, requestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, signingMethod, "", nil, nil, nil)

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	addTokenToRequest(req, tokenMethod, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}` + "\n", string(body), "they should not be equal")
}

func runTestWithDiscoverySuccess(t *testing.T, signingMethod jwt.SigningMethod, certificatePath string, setIssuer bool, setOidcDiscoveryUri bool, setJwksUri bool, tokenMethod TokenMethod) {
	certificate, jwksServer, middlwareServer, err := buildTestServers(certificatePath, certificatePath, func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		if setIssuer {
			jwtConfiguration.Issuer = issuerUri.String()
		}
		if setOidcDiscoveryUri {
			jwtConfiguration.DiscoveryAddress = oidcDiscoveryUri.String()
		}
		if setJwksUri {
			jwtConfiguration.JwksAddress = jwksUri.String()
		}

		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, requestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, signingMethod, "", nil, nil, nil)

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	addTokenToRequest(req, tokenMethod, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, `{"RequestUri":"/", "Referer":""}` + "\n", string(body), "they should be equal")
}

func runTestWithDiscoveryFailure(t *testing.T, signingMethod jwt.SigningMethod, serverCertificatePath string, clientCertificatePath string, setIssuer bool, setOidcDiscoveryUri bool, setJwksUri bool, tokenMethod TokenMethod) {
	_, jwksServer, middlwareServer, err := buildTestServers(serverCertificatePath, serverCertificatePath, func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		if setIssuer {
			jwtConfiguration.Issuer = issuerUri.String()
		}
		if setOidcDiscoveryUri {
			jwtConfiguration.DiscoveryAddress = oidcDiscoveryUri.String()
		}
		if setJwksUri {
			jwtConfiguration.JwksAddress = jwksUri.String()
		}

		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	clientCertificate, err := getCertificateFromPath(clientCertificatePath, clientCertificatePath)
	if err != nil {
		panic(err)
	}

	client, _, _, signedToken, requestUrl, _, err := buildTestClient(clientCertificate, "", jwksServer, middlwareServer, signingMethod, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	addTokenToRequest(req, tokenMethod, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, `{"RequestUri":"/", "Referer":""}` + "\n", string(body), "they should not be equal")
}

/***************************/

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

/***************************/

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
	//As long as the cert we are using is different
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES256, "signing/es512", "signing/es256", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES384, "signing/es256", "signing/es384", TokenMethodAuthorizationHeader)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES512, "signing/es256", "signing/es512", TokenMethodAuthorizationHeader)
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
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES256, "signing/another.es256", "signing/es256", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES384, "signing/another.es384", "signing/es384", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES512, "signing/another.es512", "signing/es512", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS256, "signing/another.rsa", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS384, "signing/another.rsa", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS512, "signing/another.rsa", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS256, "signing/another.rsa", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS384, "signing/another.rsa", "signing/rsa", TokenMethodQuerystring)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS512, "signing/another.rsa", "signing/rsa", TokenMethodQuerystring)
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
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES256, "signing/another.es256", "signing/es256", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES384, "signing/another.es384", "signing/es384", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodES512, "signing/another.es512", "signing/es512", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS256, "signing/another.rsa", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS384, "signing/another.rsa", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodPS512, "signing/another.rsa", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS256, "signing/another.rsa", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS384, "signing/another.rsa", "signing/rsa", TokenMethodCookie)
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS512, "signing/another.rsa", "signing/rsa", TokenMethodCookie)
}

func TestWithSignedRsaPublicKeySuccess(t *testing.T) {
	runTestWithPublicKeySuccess(t, jwt.SigningMethodRS256, "../../integration/fixtures/https/snitest.com", TokenMethodAuthorizationHeader)
}

func TestWithRsaPublicKeySignedWithWrongPrivateKeyFailure(t *testing.T) {
	runTestWithPublicKeyFailure(t, jwt.SigningMethodRS256, "../../integration/fixtures/https/snitest.com", "signing/rsa", TokenMethodAuthorizationHeader)
}

/***************************/

func TestWithOidcInAuthorizationHeaderSuccess(t *testing.T) {
	runTestWithDiscoverySuccess(t, jwt.SigningMethodES256, "signing/es256", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodES384, "signing/es384", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodES512, "signing/es512", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodPS256, "signing/rsa", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodPS384, "signing/rsa", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodPS512, "signing/rsa", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodRS256, "signing/rsa", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodRS384, "signing/rsa", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoverySuccess(t, jwt.SigningMethodRS512, "signing/rsa", true, false, false, TokenMethodAuthorizationHeader)
}

func TestWithOidcInAuthorizationHeaderFailure(t *testing.T) {
	runTestWithDiscoveryFailure(t, jwt.SigningMethodES256, "signing/es256", "signing/another.es256", true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodES384, "signing/es384", "signing/another.es384",true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodES512, "signing/es512", "signing/another.es512",true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodPS256, "signing/rsa", "signing/another.rsa",true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodPS384, "signing/rsa", "signing/another.rsa",true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodPS512, "signing/rsa", "signing/another.rsa",true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodRS256, "signing/rsa", "signing/another.rsa",true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodRS384, "signing/rsa", "signing/another.rsa",true, false, false, TokenMethodAuthorizationHeader)
	runTestWithDiscoveryFailure(t, jwt.SigningMethodRS512, "signing/rsa", "signing/another.rsa",true, false, false, TokenMethodAuthorizationHeader)
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
	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, _, _, _, requestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	expectedBody := "\n"
	assert.EqualValues(t, expectedBody, string(body), "they should be equal")
}

func TestWithNoAuthenticationAndSsoProvidedFailure(t *testing.T) {
	var expectedSsoAddressTemplate string

	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

		expectedSsoAddressTemplate = jwtConfiguration.SsoAddressTemplate

		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, nonce, _, _, requestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	res, err := client.Do(req)

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

	redirectUrlRegex := strings.Replace(strings.Replace(strings.Replace(templateToRegexFixer(expectedSsoAddressTemplate), "{{.CallbackUrl}}", "(.*)", -1), "{{.State}}", "(.*)", -1), "{{.Nonce}}", "(.*)", -1)
	expectedRedirectUrlRegex, err := regexp.Compile(redirectUrlRegex)
	expectedRedirectUrlMatches := expectedRedirectUrlRegex.FindStringSubmatch(bodyMatch)
	assert.Len(t, expectedRedirectUrlMatches, 4, "Expect 4 matches")
	nonceMatch := expectedRedirectUrlMatches[1]
	redirectUriMatch := expectedRedirectUrlMatches[2]
	stateMatch := expectedRedirectUrlMatches[3]

	assert.Equal(t, nonce, nonceMatch, "nonce should be specified")
	assert.EqualValues(t, url.QueryEscape(expectedRedirectUri.String()), redirectUriMatch, "redirect_uri should be specified")
	assert.NotEqual(t, url.QueryEscape(""), stateMatch, "state should be specified")
}

/***************************/

func TestWithRedirectFromSsoButIdTokenIsStoredInBookmarkSuccess(t *testing.T) {
	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

		return jwtConfiguration
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, _, _, _, clientRequestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	//Work out the url that the SSO would redirect back to
	expectedReturnUrl := fmt.Sprintf("%s://%s%s?%s=%s", clientRequestUrl.Scheme, clientRequestUrl.Host, callbackPath, redirectUriQuerystringParameterName, url.QueryEscape(clientRequestUrl.String()))
	expectedRedirectorUrl := fmt.Sprintf("%s://%s%s", clientRequestUrl.Scheme, clientRequestUrl.Host, redirectorPath)

	req := testhelpers.MustNewRequest(http.MethodGet, expectedReturnUrl, nil)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)

//	expectedBodyTemplate := "\n<!DOCTYPE html><html><head><title></title></head><body>\n<script>\nfunction getBookMarkParameterByName(name, url) {\n    if (!url) url = window.location.hash;\n    name = name.replace(/[\\[\\]]/g, \"\\\\$&\");\n    var regex = new RegExp(\"[#&?]\" + name + \"(=([^&#]*)|&|#|$)\"), results = regex.exec(url);\n    if (!results) return null;\n    if (!results[2]) return '';\n    return decodeURIComponent(results[2].replace(/\\+/g, \" \"));\n}\n\nstate = getBookMarkParameterByName('state');\nif (state) {\n\tid_token = getBookMarkParameterByName('id_token');\n\tif (id_token) {\n\n\t\tdocument.cookie = 'id_token=' + id_token + '; domain=' + document.domain + '; path=/; secure';\n\t\twindow.location.replace('%s?' + state);\n\n\t}\n}\n</script>\nPlease change the '#' in the url to '&' and goto link\n</body></html>\n\n"
	expectedBodyTemplate := "\n<!DOCTYPE html><html><head><title></title></head><body>\n<script>\nfunction getBookMarkParameterByName(name, url) {\n    if (!url) url = window.location.hash;\n    name = name.replace(/[\\[\\]]/g, \"\\\\$&\");\n    var regex = new RegExp(\"[#&?]\" + name + \"(=([^&#]*)|&|#|$)\"), results = regex.exec(url);\n    if (!results) return null;\n    if (!results[2]) return '';\n    return decodeURIComponent(results[2].replace(/\\+/g, \" \"));\n}\n\nfunction post(path, params, method) {\n    method = method || \"post\"; // Set method to post by default if not specified.\n\n    // The rest of this code assumes you are not using a library.\n    // It can be made less wordy if you use one.\n    var form = document.createElement(\"form\");\n    form.setAttribute(\"method\", method);\n    form.setAttribute(\"action\", path);\n\n    for(var key in params) {\n        if(params.hasOwnProperty(key)) {\n            var hiddenField = document.createElement(\"input\");\n            hiddenField.setAttribute(\"type\", \"hidden\");\n            hiddenField.setAttribute(\"name\", key);\n            hiddenField.setAttribute(\"value\", params[key]);\n\n            form.appendChild(hiddenField);\n        }\n    }\n\n    document.body.appendChild(form);\n    form.submit();\n}\n\nstate = getBookMarkParameterByName('state');\nif (state) {\n\tid_token = getBookMarkParameterByName('id_token');\n\tif (id_token) {\n\n\t\tpost('%s?' + state, {id_token: id_token});\n\n\t}\n}\n</script>\nPlease change the '#' in the url to '&' and goto link\n</body></html>\n\n"

	assert.EqualValues(t, fmt.Sprintf(expectedBodyTemplate, expectedRedirectorUrl), string(body), "Should be equal")
}

func TestRedirectorWithValidCookieAndValidHashSuccess(t *testing.T) {
	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

		return jwtConfiguration
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, clientRequestUrl, expectedRedirectorUrl, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, expectedRedirectorUrl.String(), nil)
	addTokenToRequest(req, TokenMethodCookie, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusSeeOther, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned" )

	if len(cookies) == 1 {
		assert.EqualValues(t, sessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Equal(time.Time{}), "Session cookie should not have this set")
		assert.True(t, cookies[0].MaxAge == 0, "Session cookie should not have this set")
	}

	body, err := ioutil.ReadAll(res.Body)
	assert.EqualValues(t, fmt.Sprintf("<a href=\"%s\">See Other</a>.\n\n", clientRequestUrl), string(body), "Should be equal")
}

func TestRedirectorWithInvalidCookieAndValidHashSuccess(t *testing.T) {
	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

		return jwtConfiguration
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, _, expectedRedirectorUrl, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, expectedRedirectorUrl.String(), nil)

	cookie := &http.Cookie{
		Name:  sessionCookieName,
		Value: signedToken + "dodgy_token",
	}
	req.AddCookie(cookie)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned" )

	if len(cookies) == 1 {
		assert.EqualValues(t, sessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Before(time.Now().UTC()), "Session cookie should be expired")
		assert.True(t, cookies[0].MaxAge < 0, "Session cookie should be expired")
	}

	body, err := ioutil.ReadAll(res.Body)
	assert.EqualValues(t, "\n", string(body), "Should be equal")
}

func TestRedirectorWithValidCookieAndValidHashAndUsingDiscoveryAddressSuccess(t *testing.T) {
	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.DiscoveryAddress = oidcDiscoveryUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

		return jwtConfiguration
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, clientRequestUrl, expectedRedirectorUrl, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, expectedRedirectorUrl.String(), nil)
	addTokenToRequest(req, TokenMethodCookie, signedToken)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusSeeOther, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned" )

	if len(cookies) == 1 {
		assert.EqualValues(t, sessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Equal(time.Time{}), "Session cookie should not have this set")
		assert.True(t, cookies[0].MaxAge == 0, "Session cookie should not have this set")
	}

	body, err := ioutil.ReadAll(res.Body)
	assert.EqualValues(t, fmt.Sprintf("<a href=\"%s\">See Other</a>.\n\n", clientRequestUrl), string(body), "Should be equal")
}

func TestRedirectorWithValidPostAndValidHashSuccess(t *testing.T) {
	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()

		return jwtConfiguration
	})

	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	client, _, _, signedToken, _, expectedRedirectorUrl, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodPost, expectedRedirectorUrl.String(), strings.NewReader("id_token=" + signedToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.EqualValues(t, http.StatusSeeOther, res.StatusCode, "they should be equal")

	cookies := res.Cookies()
	assert.Len(t, cookies, 1, "At least one cookie should have been returned" )

	if len(cookies) == 1 {
		assert.EqualValues(t, sessionCookieName, cookies[0].Name, "Session cookie for id_token not present")
		assert.True(t, cookies[0].Expires.Equal(time.Time{}), "Session cookie should not have this set")
		assert.True(t, cookies[0].MaxAge == 0, "Session cookie should not have this set")
	}

	body, err := ioutil.ReadAll(res.Body)
	assert.EqualValues(t, "", string(body), "Should be equal")
}

func TestWithNoAuthenticationAndIgnorePathMatched(t *testing.T) {
	var expectedSsoAddressTemplate string

	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()
		jwtConfiguration.IgnorePathRegex = "/"

		expectedSsoAddressTemplate = jwtConfiguration.SsoAddressTemplate

		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, _, _, _, requestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	stringBody := string(body)

	assert.Equal(t, "{\"RequestUri\":\"/\", \"Referer\":\"\"}\n", stringBody, "they should equal")
}

func TestWithNoAuthenticationAndIgnorePathNotMatched(t *testing.T) {
	var expectedSsoAddressTemplate string

	certificate, jwksServer, middlwareServer, err := buildTestServers("signing/rsa", "signing/rsa", func(jwtConfiguration *types.Jwt, certificate *traefiktls.Certificate, ssoAddressTemplate string, issuerUri *url.URL, oidcDiscoveryUri *url.URL, jwksUri *url.URL) (*types.Jwt){
		jwtConfiguration.Issuer = issuerUri.String()
		jwtConfiguration.SsoAddressTemplate = ssoAddressTemplate
		jwtConfiguration.UrlMacPrivateKey = certificate.KeyFile.String()
		jwtConfiguration.IgnorePathRegex = "!/"

		expectedSsoAddressTemplate = jwtConfiguration.SsoAddressTemplate

		return jwtConfiguration
	})
	if err != nil {
		panic(err)
	}
	defer jwksServer.Close()
	defer middlwareServer.Close()

	//client, nonce, issuedAt, signedToken, expectedRedirectorUrl, err
	client, nonce, _, _, requestUrl, _, err := buildTestClient(certificate, "", jwksServer, middlwareServer, jwt.SigningMethodRS256, "", nil, nil, nil)
	if err != nil {
		panic(err)
	}

	req := testhelpers.MustNewRequest(http.MethodGet, requestUrl.String(), nil)
	res, err := client.Do(req)

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

	redirectUrlRegex := strings.Replace(strings.Replace(strings.Replace(templateToRegexFixer(expectedSsoAddressTemplate), "{{.CallbackUrl}}", "(.*)", -1), "{{.State}}", "(.*)", -1), "{{.Nonce}}", "(.*)", -1)
	expectedRedirectUrlRegex, err := regexp.Compile(redirectUrlRegex)
	expectedRedirectUrlMatches := expectedRedirectUrlRegex.FindStringSubmatch(bodyMatch)
	assert.Len(t, expectedRedirectUrlMatches, 4, "Expect 4 matches")
	nonceMatch := expectedRedirectUrlMatches[1]
	redirectUriMatch := expectedRedirectUrlMatches[2]
	stateMatch := expectedRedirectUrlMatches[3]

	assert.Equal(t, nonce, nonceMatch, "nonce should be specified")
	assert.EqualValues(t, url.QueryEscape(expectedRedirectUri.String()), redirectUriMatch, "redirect_uri should be specified")
	assert.NotEqual(t, url.QueryEscape(""), stateMatch, "state should be specified")
}
