package auth

import (
	"encoding/base64"
	"fmt"

	"github.com/Cimpress-MCP/go-jwks-api-auth"
	"github.com/auth0/go-jwt-middleware"
	"github.com/containous/traefik/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/urfave/negroni"
)

func Jwt(config *types.Jwt) negroni.HandlerFunc {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			var (
				decoded []byte
				err     error
			)
			// If kid exists then get the public key from the JWT's issuer, otherwise use client secret
			if _, ok := token.Header["kid"]; ok && config.RS256 != nil && config.RS256.JwksTargetIssuer != "" {
				decoded, err = jwks.GetPublicKey(token, config.RS256.JwksTargetIssuer, config.RS256.JwksTargetAudience)
			} else if config.HS256 != nil && config.HS256.ClientSecret != "" {
				decoded, err = base64.URLEncoding.DecodeString(config.HS256.ClientSecret)
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
