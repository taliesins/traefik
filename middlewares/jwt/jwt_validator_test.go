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
)

// defaultAuthorizationHeaderName is the default header name where the Auth
// token should be written
const defaultAuthorizationHeaderName = "Authorization"

func signHeaderWithClientSecret(req *http.Request, clientSecret string) error{
	signingKey := []byte(clientSecret)

	claims := &jwt.StandardClaims{
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return err
	}
	req.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", signedToken))

	return nil
}

func signHeaderWithCertificate(req *http.Request, certificate *traefiktls.Certificate, signingMethod jwt.SigningMethod) error {
	privateKeyPemData, err := certificate.KeyFile.Read()
	if err != nil {
		return err
	}

	privateKey, err := GetPrivateKeyFromPem(privateKeyPemData)
	if err != nil {
		return err
	}

	claims := &jwt.StandardClaims{
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return err
	}

	req.Header.Set(defaultAuthorizationHeaderName, fmt.Sprintf("bearer %v", signedToken))

	return nil
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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodPS256)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodPS384)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodPS512)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS384)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS512)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithCertificate(req, certificate, jwt.SigningMethodRS256)

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithClientSecret(req, "mySecret")

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})
	n := negroni.New(jwtMiddleware.Handler)
	n.UseHandler(handler)
	ts := httptest.NewServer(n)
	defer ts.Close()

	client := &http.Client{}
	req := testhelpers.MustNewRequest(http.MethodGet, ts.URL, nil)
	signHeaderWithClientSecret(req, "mySecret")

	res, err := client.Do(req)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.NotEqual(t, "traefik\n", string(body), "they should not be equal")
}
