package jwt

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	traefiktls "github.com/containous/traefik/tls"
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/testhelpers"
	"github.com/containous/traefik/types"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/negroni"
	"github.com/dgrijalva/jwt-go"
	"runtime"
	"path"
	"gopkg.in/square/go-jose.v1"
	"encoding/json"
	"crypto/ecdsa"
	"crypto/rsa"
	"reflect"
)

// defaultAuthorizationHeaderName is the default header name where the Auth
// token should be written
const defaultAuthorizationHeaderName = "Authorization"

func signHeaderWithClientSecret(req *http.Request, clientSecret string, claims *jwt.StandardClaims) error{
	signingKey := []byte(clientSecret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return err
	}
	req.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", signedToken))

	return nil
}

func signHeaderWithCertificate(req *http.Request, certificate *traefiktls.Certificate, signingMethod jwt.SigningMethod, kid string, claims *jwt.StandardClaims) error {
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

	req.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", signedToken))

	return nil
}

func getJsonWebset(certificate *traefiktls.Certificate)(*jose.JsonWebKeySet, error){
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
		Keys:[]jose.JsonWebKey{
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


func TestWithES256Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/es256")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodES256, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithES384Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/es384")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodES384, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}


func TestWithES512Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/es512")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodES512, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}


func TestWithPS256Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodPS256, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithPS384Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodPS384, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithPS512Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodPS512, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithRS256Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithRS384Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS384, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithRS512Success(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS512, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithUnsignedRsaPublicKeySuccess(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithSignedRsaPublicKeySuccess(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "../../integration/fixtures/https/snitest.com")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.cert", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithRsaPublicKeySignedWithWrongPrivateKeyFailure(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.cert", path.Join(path.Dir(filename), "../../integration/fixtures/https/snitest.com"))),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", path.Join(path.Dir(filename), "signing/rsa"))),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	certContent, err := certificate.CertFile.Read()
	if err != nil{
		panic(err)
	}

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Cert: string(certContent),
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := ""
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256, kid, claims)

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, "traefik\n", string(body), "they should not be equal")
}

func TestWithClientSecretSuccess(t *testing.T) {
	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		ClientSecret: "mySecret",
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithClientSecret(req, "mySecret", claims)

	res, err := client.Do(req)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithClientSecretWrongSecret(t *testing.T) {
	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		ClientSecret: "mySecretWrong",
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithClientSecret(req, "mySecret", claims)

	res, err := client.Do(req)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, "traefik\n", string(body), "they should not be equal")
}

func TestWithRS256UsingJwksUriSuccess(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if  !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if  !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if  err != nil {
		panic(err)
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if  err != nil {
		panic(err)
	}

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonWebKeySetJson)
	}))
	defer jwksServer.Close()

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		JwksAddress: jwksServer.URL,
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := jsonWebKeySet.Keys[0].KeyID
	claims := &jwt.StandardClaims{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	err = signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256, kid, claims)
	if  err != nil {
		panic(err)
	}

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

func TestWithRS256UsingIssuerUriSuccess(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), "signing/rsa")

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(fmt.Sprintf("%s.crt", certPath)),
		KeyFile:  traefiktls.FileOrContent(fmt.Sprintf("%s.key", certPath)),
	}

	if !certificate.CertFile.IsPath() {
		panic(fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile)))
	}

	if !certificate.KeyFile.IsPath() {
		panic(fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile)))
	}

	jsonWebKeySet, err := getJsonWebset(certificate)
	if  err != nil {
		panic(err)
	}

	jsonWebKeySetJson, err := json.Marshal(jsonWebKeySet)
	if  err != nil {
		panic(err)
	}

	//https://login.microsoftonline.com/f51cd401-5085-4669-9352-9e0b88334eb5/discovery/v2.0/keys
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if (r.RequestURI == "/.well-known/openid-configuration") {
			jwksUri := fmt.Sprintf("http://%s/common/discovery/keys", r.Host)
			fmt.Fprintln(w, fmt.Sprintf(`{"jwks_uri":"%s"}`, jwksUri))
		} else if (r.RequestURI == "/common/discovery/keys") {
			w.Write(jsonWebKeySetJson)
		} else {
			panic("Don't know how to handle request")
		}
	}))
	defer jwksServer.Close()

	jwtMiddleware, err := NewJwtValidator(&types.Jwt{
		Issuer: jwksServer.URL,
	}, &tracing.Tracing{})
	assert.NoError(t, err, "there should be no error")

	kid := jsonWebKeySet.Keys[0].KeyID
	claims := &jwt.StandardClaims{
		Issuer:jwksServer.URL,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	err = signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256, kid, claims)
	if  err != nil {
		panic(err)
	}

	res, err := client.Do(req)

	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}

