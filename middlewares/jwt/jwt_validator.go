package jwt

import (
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/types"
	"github.com/urfave/negroni"
	"github.com/auth0/go-jwt-middleware"

	"encoding/base64"
	"fmt"
	jwks "github.com/containous/traefik/middlewares/jwt/jwk"
	"github.com/dgrijalva/jwt-go"
)

// Authenticator is a middleware that provides HTTP basic and digest authentication
type JwtValidator struct {
	Handler negroni.Handler
}

type tracingJwtValidator struct {
	name           string
	handler        negroni.Handler
	clientSpanKind bool
}

func NewJwtValidator(config *types.Jwt, tracingMiddleware *tracing.Tracing) (*JwtValidator, error) {
	jwtValidator := JwtValidator{}
	tracingJwtValidator := tracingJwtValidator{}
	tracingJwtValidator.handler = createAuthJwtHandler(config)
	tracingJwtValidator.name = "Auth Jwt"
	tracingJwtValidator.clientSpanKind = false

	if tracingMiddleware != nil {
		jwtValidator.Handler = tracingMiddleware.NewNegroniHandlerWrapper(tracingJwtValidator.name, tracingJwtValidator.handler, tracingJwtValidator.clientSpanKind)
	} else {
		jwtValidator.Handler = tracingJwtValidator.handler
	}
	return &jwtValidator, nil
}

func createAuthJwtHandler(config *types.Jwt) negroni.HandlerFunc {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			var (
				decoded []byte
				err     error
			)

			claims := token.Claims.(jwt.MapClaims)

			// Get iss from JWT and validate against desired iss
			if claims["iss"].(string) != config.Issuer {
				return nil, fmt.Errorf("cannot validate iss claim")
			}

			// Get audience from JWT and validate against desired audience
			if claims["aud"].(string) != config.Audience {
				return nil, fmt.Errorf("Cannot validate audience claim")
			}

			// If kid exists then get the public key from the JWT's issuer, otherwise use client secret
			if _, ok := token.Header["kid"]; ok && (config.Issuer != "" || config.JwksAddress != "") {
				decoded, err = jwks.GetJwksPublicKey(token, config.Issuer, config.JwksAddress)
			} else if config.ClientSecret != "" && (token.Header["alg"] == "HS256" || token.Header["alg"] == "HS384" || token.Header["alg"] == "HS512") {
				decoded, err = base64.URLEncoding.DecodeString(config.ClientSecret)
			} else if config.CertFile != "" {
				decoded, err = jwks.GetPublicKeyFile(token, config.CertFile)
			} else {
				err = fmt.Errorf("Jwt token does not match any allowed algorithm type")
			}
			if err != nil {
				return nil, err
			}

			return decoded, nil
		},
	})

	return jwtMiddleware.HandlerWithNext
}
