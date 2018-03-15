package jwt

import (
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/types"
	"github.com/urfave/negroni"
	"github.com/auth0/go-jwt-middleware"
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

			//Get alg to use
			algHeader, ok := token.Header["alg"]
			if !ok{
				return nil, fmt.Errorf("Cannot get alg to use")
			}
			alg := algHeader.(string)

			kid := ""
			kidHeader, ok := token.Header["kid"]
			if ok{
				kid = kidHeader.(string)
			}

			if config.ClientSecret != "" && kid == "" && (alg == "HS256" || alg == "HS384" || alg == "HS512") {
				//Standard client Secret Jwt Validation
				decoded = []byte(config.ClientSecret)
				return decoded, nil
			}

			if config.CertFile != "" && (kid == "" || (config.Issuer == "" && config.JwksAddress == "")) {
				//Standard certificate Jwt validation
				decoded, err = jwks.GetPublicKeyFile(alg, config.CertFile)
				if err != nil {
					return nil, err
				}
				return decoded, nil
			}

			// If kid exists then get the public key from the JWT's issuer
			if kid != "" && (config.Issuer != "" || config.JwksAddress != "") {
				claims := token.Claims.(jwt.MapClaims)

				iss := ""
				if claims["iss"] != nil {
					iss = claims["iss"].(string)
				}

				aud := ""
				if claims["aud"] != nil {
					aud = claims["aud"].(string)
				}

				exp := int64(0)
				if claims["exp"] != nil {
					exp = claims["exp"].(int64)
				}

				// Get iss from JWT and validate against desired iss
				if config.Issuer != "" && iss != config.Issuer {
					return nil, fmt.Errorf("Cannot validate iss claim")
				}

				// Get audience from JWT and validate against desired audience
				if config.Audience != "" && aud != config.Audience {
					return nil, fmt.Errorf("Cannot validate audience claim")
				}

				decoded, err = jwks.GetJwksPublicKey(alg, kid, iss, exp, config.Issuer, config.JwksAddress)

				if err != nil {
					return nil, err
				}
				return decoded, nil
			}

			return nil, fmt.Errorf("Jwt token does not match any allowed algorithm type")
		},
	})

	return jwtMiddleware.HandlerWithNext
}
