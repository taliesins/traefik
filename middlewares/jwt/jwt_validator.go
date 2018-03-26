package jwt

import (
	"fmt"
	"github.com/auth0/go-jwt-middleware"
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/server/uuid"
	"github.com/containous/traefik/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/urfave/negroni"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"
)

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
	jwtHandler, err := createJwtHandler(config)
	if err != nil {
		return nil, err
	}

	tracingJwtValidator := tracingJwtValidator{}
	tracingJwtValidator.handler = jwtHandler
	tracingJwtValidator.name = "Auth Jwt"
	tracingJwtValidator.clientSpanKind = false

	if tracingMiddleware != nil {
		jwtValidator.Handler = tracingMiddleware.NewNegroniHandlerWrapper(tracingJwtValidator.name, tracingJwtValidator.handler, tracingJwtValidator.clientSpanKind)
	} else {
		jwtValidator.Handler = tracingJwtValidator.handler
	}
	return &jwtValidator, nil
}

func createJwtHandler(config *types.Jwt) (negroni.HandlerFunc, error) {
	var err error

	//Redirect url for SSO
	var ssoRedirectUrlTemplate *template.Template
	if config.SsoAddressTemplate != "" {
		ssoRedirectUrlTemplate, err = getSsoRedirectUrlTemplate(config.SsoAddressTemplate)
		if err != nil {
			return nil, err
		}
	} else {
		ssoRedirectUrlTemplate = nil
	}

	//Standard client secret Jwt validation
	var clientSecret []byte
	if config.ClientSecret != "" {
		clientSecret = []byte(config.ClientSecret)
	} else {
		clientSecret = nil
	}

	//Standard certificate Jwt validation
	var publicKey interface{}
	if config.PublicKey != "" {
		publicKey, _, err = GetPublicKeyFromFileOrContent(config.PublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		publicKey = nil
	}

	//Url hash using secret
	var urlHashClientSecret []byte
	if config.UrlMacClientSecret != "" {
		urlHashClientSecret = []byte(config.UrlMacClientSecret)
	} else {
		urlHashClientSecret = nil
	}

	//Url hash using private key
	var urlHashPrivateKey interface{}
	if config.UrlMacPrivateKey != "" {
		urlHashPrivateKey, _, err = GetPrivateKeyFromFileOrContent(config.UrlMacPrivateKey)
		if err != nil {
			return nil, err
		}
	} else {
		urlHashPrivateKey = nil
	}

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, errorMessage string) {
			if ssoRedirectUrlTemplate == nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			nonce := uuid.Get()
			issuedAt := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)

			var redirectorUrl *url.URL
			if urlHashPrivateKey != nil {
				redirectorUrl, err = getRedirectorUrl(r, urlHashPrivateKey, nonce, issuedAt)
			} else if urlHashClientSecret != nil {
				redirectorUrl, err = getRedirectorUrl(r, urlHashClientSecret, nonce, issuedAt)
			} else {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			if strings.HasPrefix(r.URL.Path, callbackPath) {
				if strings.HasPrefix(r.Referer(), callbackPath) {
					//Referrer was from callbackPath, so stop endless loop
					http.Error(w, "", http.StatusUnauthorized)
					return
				}

				//callback page for sso
				ssoCallbackPage, err := renderSsoCallbackPageTemplate(redirectorUrl)
				if err != nil {
					http.Error(w, "", http.StatusUnauthorized)
					return
				}

				//The SSO is probably making the callback, but it must have passed id_token as bookmark so we can't access it from server side, so fall back to javascript to set cookie with value
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, ssoCallbackPage)
				return
			}

			ssoRedirectUrl, err := renderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate, redirectorUrl, nonce, issuedAt)
			if err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			//This will allow browsers to default to implicit flow
			redirectToSsoPage, err := renderRedirectToSsoPageTemplate(ssoRedirectUrl, "")
			if err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, redirectToSsoPage)
		},
		Extractor: func(r *http.Request) (token string, err error) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				authHeaderParts := strings.Split(authHeader, " ")
				if len(authHeaderParts) == 2 && strings.ToLower(authHeaderParts[0]) == "bearer" {
					token = authHeaderParts[1]
					return token, nil
				}
			}

			sessionCookie, err := r.Cookie(sessionCookieName)
			if err == nil {
				token = sessionCookie.Value
				if token != "" {
					return token, nil
				}
			}

			query := r.URL.Query()
			token = query.Get("id_token")
			if token != "" {
				return token, nil
			}

			//SSO can post to specific url to set token_id (could also be used for forms authentication?)
			if strings.HasPrefix(r.URL.Path, callbackPath) {
				//TODO: SSO posts back the id_token
			}

			return "", nil
		},
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			algHeader, ok := token.Header["alg"]
			if !ok {
				return nil, fmt.Errorf("Cannot get alg to use")
			}
			alg := algHeader.(string)

			//TODO: Validate allowed algs here
			//return nil, fmt.Errorf("Jwt token does not match any allowed algorithm type")

			kid := ""
			kidHeader, ok := token.Header["kid"]
			if ok {
				kid = kidHeader.(string)
			}

			if clientSecret != nil && kid == "" && (alg == "HS256" || alg == "HS384" || alg == "HS512") {
				return clientSecret, nil
			}

			if publicKey != nil && (kid == "" || (config.Issuer == "" && config.JwksAddress == "" && config.DiscoveryAddress == "")) {
				//TODO: Validate for ES256,ES384,ES512?
				return publicKey, nil
			}

			// If kid exists then we using dynamic public keys
			if kid != "" && (config.Issuer != "" || config.JwksAddress != "" || config.DiscoveryAddress != "") {
				claims := token.Claims.(jwt.MapClaims)

				iss := ""
				if claims["iss"] != nil {
					iss = claims["iss"].(string)
				}

				aud := ""
				if claims["aud"] != nil {
					aud = claims["aud"].(string)
				}

				//Todo: Add all the validations required
				if config.Issuer != "" && iss != config.Issuer {
					return nil, fmt.Errorf("Cannot validate iss claim")
				}

				if config.Audience != "" && aud != config.Audience {
					return nil, fmt.Errorf("Cannot validate audience claim")
				}

				var (
					err       error
					publicKey interface{}
				)

				//public keys are calculated JIT as they are dynamic
				if config.JwksAddress != "" {
					publicKey, _, err = GetPublicKeyFromJwksUri(kid, config.JwksAddress)
				} else if config.DiscoveryAddress != "" {
					publicKey, _, err = GetPublicKeyFromOpenIdConnectDiscoveryUri(kid, config.DiscoveryAddress)
				} else if config.Issuer != "" {
					publicKey, _, err = GetPublicKeyFromIssuerUri(kid, config.Issuer)
				}

				if err != nil {
					return nil, err
				}

				//TODO: Validate for ES256,ES384,ES512?
				return publicKey, nil
			}

			return nil, fmt.Errorf("Jwt token does not match any allowed algorithm type")
		},
	})

	jwtHandlerFunc := func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		//Todo: White list of paths that do not have to be authenticated

		if strings.HasPrefix(r.URL.Path, robotsPath) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "User-agent: *\nDisallow: /")
			return
		}

		err := jwtMiddleware.CheckJWT(w, r)

		if err == nil && strings.HasPrefix(r.URL.Path, redirectorPath) {
			// Unauthorized page with javascript to capture id_token from bookmark has run and redirected here
			var redirectUrl *url.URL
			if urlHashPrivateKey != nil {
				redirectUrl, err = getRedirectUrl(r, urlHashPrivateKey)
			} else if urlHashClientSecret != nil {
				redirectUrl, err = getRedirectUrl(r, urlHashClientSecret)
			} else {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			http.Redirect(w, r, redirectUrl.String(), http.StatusSeeOther)
			return
		}

		// If there was an error, do not call next.
		if err == nil && next != nil {
			next(w, r)
		}
	}

	return jwtHandlerFunc, nil
}
