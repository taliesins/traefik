package jwt

import (
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/types"
	"github.com/urfave/negroni"
	"github.com/auth0/go-jwt-middleware"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"text/template"
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

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ErrorHandler:func(w http.ResponseWriter, r *http.Request, errorMessage string){
			if ssoRedirectUrlTemplate == nil {
				http.Error(w, errorMessage, http.StatusUnauthorized)
				return
			}

			if strings.HasPrefix(r.URL.Path, callbackPath)  {
				query := r.URL.Query()

				//Anonymous user going directly to redirect url, so ignore it
				redirectUrl := query.Get(redirectUriQuerystringParameterName)
				if redirectUrl == "" {
					http.Error(w, errorMessage, http.StatusUnauthorized)
					return
				}

				//The SSO is probably making the callback, but it must have passed id_token as bookmark so we can't access it from server side, so fall back to javascript to set cookie with value
				idTokenInBookmarkRedirectPage, err := renderIdTokenInBookmarkRedirectPageTemplate(redirectUrl, sessionCookieName, idTokenBookmarkParameterName)
				if err != nil {
					http.Error(w, errorMessage, http.StatusUnauthorized)
					return
				} else {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, idTokenInBookmarkRedirectPage)
				}
			}

			callbackRedirectUrl, err := renderCallbackRedirectUrlTemplate(r, callbackPath, redirectUriQuerystringParameterName)
			if err != nil {
				http.Error(w, errorMessage, http.StatusUnauthorized)
				return
			}

			ssoRedirectUrl, err := renderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate, callbackRedirectUrl)
			if err != nil {
				http.Error(w, errorMessage, http.StatusUnauthorized)
				return
			}

			redirectToSingleSignOnPage, err := renderRedirectToSsoPageTemplate(ssoRedirectUrl, errorMessage)
			if err != nil {
				http.Error(w, errorMessage, http.StatusUnauthorized)
				return
			}

			http.Error(w, redirectToSingleSignOnPage, http.StatusUnauthorized)
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

			query := r.URL.Query()

			token = query.Get("id_token")
			if token != "" {
				return token, nil
			}

			sessionCookie, err := r.Cookie(sessionCookieName)
			if err == nil {
				token = sessionCookie.Value
				if token != "" {
					return token, nil
				}
			}

			//SSO can post to specific url to set token_id (could also be used for forms authentication?)
			if strings.HasPrefix(r.URL.Path, callbackPath) {
				//TODO: SSO posts back the id_token
			}

			return "", nil
		},
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			algHeader, ok := token.Header["alg"]
			if !ok{
				return nil, fmt.Errorf("Cannot get alg to use")
			}
			alg := algHeader.(string)

			//TODO: Validate allowed algs here
			//return nil, fmt.Errorf("Jwt token does not match any allowed algorithm type")

			kid := ""
			kidHeader, ok := token.Header["kid"]
			if ok{
				kid = kidHeader.(string)
			}

			if clientSecret != nil && kid == "" && (alg == "HS256" || alg == "HS384" || alg == "HS512") {
				return clientSecret, nil
			}

			if publicKey != nil && (kid == "" || (config.Issuer == "" && config.JwksAddress == "" && config.OidcDiscoveryAddress == "")) {
				//TODO: Validate for ES256,ES384,ES512?
				return publicKey, nil
			}

			// If kid exists then we using dynamic public keys
			if kid != "" && (config.Issuer != "" || config.JwksAddress != "" || config.OidcDiscoveryAddress != "") {
				claims := token.Claims.(jwt.MapClaims)

				iss := ""
				if claims["iss"] != nil {
					iss = claims["iss"].(string)
				}

				aud := ""
				if claims["aud"] != nil {
					aud = claims["aud"].(string)
				}

				if config.Issuer != "" && iss != config.Issuer {
					return nil, fmt.Errorf("Cannot validate iss claim")
				}

				if config.Audience != "" && aud != config.Audience {
					return nil, fmt.Errorf("Cannot validate audience claim")
				}

				var (
					err                       error
					publicKey                 interface{}
				)

				//public keys are calculated JIT as they are dynamic
				if config.JwksAddress != "" {
					publicKey, _, err = GetPublicKeyFromJwksUri(kid, config.JwksAddress)
				} else if config.OidcDiscoveryAddress != "" {
					publicKey, _, err = GetPublicKeyFromOpenIdConnectDiscoveryUri(kid, config.OidcDiscoveryAddress)
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

	jwtHandlerFunc := func (w http.ResponseWriter, r *http.Request, next http.HandlerFunc){
		err := jwtMiddleware.CheckJWT(w, r)

		if err == nil && strings.HasPrefix(r.URL.Path, callbackPath) {
			//SSO might have redirected back here and supplied id_token so we can now redirect to redirct_uri
			query := r.URL.Query()

			//Logged in user going directly to redirect url, so ignore it
			redirectUrl := query.Get(redirectUriQuerystringParameterName)
			if redirectUrl == "" {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			//Redirect user to the uri the triggered authentication request
			/*
			When logging in with SSO we would loose any POST data, so its safer to assume that a login to run a GET vs a POST

			https://www.pmg.com/blog/301-302-303-307-many-redirects/
			303 See Other - The response to the request can be found under another URI using a GET method. When received in response to a PUT, it should be assumed that the server has received the data and the redirect should be issued with a separate GET message.
			*/
			http.Redirect(w, r, redirectUrl, http.StatusSeeOther)

			return
		}

		// If there was an error, do not call next.
		if err == nil && next != nil {
			next(w, r)
		}
	}

	return jwtHandlerFunc, nil
}