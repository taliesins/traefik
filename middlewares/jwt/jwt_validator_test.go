package jwt

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"encoding/base64"

	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/testhelpers"
	"github.com/containous/traefik/types"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/negroni"
	"github.com/dgrijalva/jwt-go"
)

// defaultAuthorizationHeaderName is the default header name where the Auth
// token should be written
const defaultAuthorizationHeaderName = "Authorization"

func signHeaderWithJwtH256(req *http.Request, clientSecret string) error{
	signingKey, err := base64.URLEncoding.DecodeString(clientSecret)
	if err != nil {
		return err
	}

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

func TestClientSecretSuccess(t *testing.T) {
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
	signHeaderWithJwtH256(req, "mySecret")

	res, err := client.Do(req)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, http.StatusOK, res.StatusCode, "they should be equal")

	body, err := ioutil.ReadAll(res.Body)
	assert.NoError(t, err, "there should be no error")
	assert.Equal(t, "traefik\n", string(body), "they should be equal")
}
