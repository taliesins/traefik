package jwt

import (
	"fmt"
	"github.com/auth0/go-jwt-middleware"
	"github.com/containous/traefik/log"
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
	"regexp"
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

func getCookie(requestUrl *url.URL, value string)(*http.Cookie){
	sessionCookie := http.Cookie{
		Name:sessionCookieName,
		Value: value,
		HttpOnly: true,
		Secure: true,
		Domain: requestUrl.Hostname(),
		Path: "/",
	}

	return &sessionCookie
}

func getExpiredSessionCookie(requestUrl *url.URL) (*http.Cookie){
	sessionCookie := getCookie(requestUrl, "")
	sessionCookie.MaxAge = -1
	sessionCookie.Expires = time.Now().Add(-100 * time.Hour)

	return sessionCookie
}

func validateClaim(claims jwt.MapClaims, claimName string, claimValidationRegex *regexp.Regexp)(error){
	if claimValidationRegex != nil {
		var claimValue string
		if claims[claimName] != nil {
			claimValue = claims[claimName].(string)
		} else {
			claimValue = ""
		}

		if !claimValidationRegex.MatchString(claimValue){
			return fmt.Errorf("failed validation on %s claim as value is %s", claimName, claimValue)
		}
	}
	return nil
}

func oidcValidationKeyGetter(config *types.Jwt, kid string, issuerValidationRegex *regexp.Regexp, audienceValidationRegex *regexp.Regexp, subjectValidationRegex *regexp.Regexp, token *jwt.Token)(publicKey interface{}, err error){
	var claims jwt.MapClaims
	if issuerValidationRegex != nil || audienceValidationRegex != nil || subjectValidationRegex != nil {
		claims = token.Claims.(jwt.MapClaims)

		err = validateClaim(claims, "iss", issuerValidationRegex)
		if err != nil {
			return nil, err
		}

		err = validateClaim(claims, "aud", audienceValidationRegex)
		if err != nil {
			return nil, err
		}

		err = validateClaim(claims, "sub", subjectValidationRegex)
		if err != nil {
			return nil, err
		}
	}

	if config.JwksAddress != "" {
		publicKey, _, err = GetPublicKeyFromJwksUri(kid, config.JwksAddress)
		if err != nil {
			log.Infof("Unable to get public key from jwks address %s for kid %s with error %s", config.JwksAddress, kid, err)
		}
	} else if config.DiscoveryAddress != "" {
		publicKey, _, err = GetPublicKeyFromOpenIdConnectDiscoveryUri(kid, config.DiscoveryAddress)
		if err != nil {
			log.Infof("Unable to get public key from discovery address %s for kid %s with error %s", config.DiscoveryAddress, kid, err)
		}
	} else if config.Issuer != "" {
		publicKey, _, err = GetPublicKeyFromIssuerUri(kid, config.Issuer)
		if err != nil {
			log.Infof("Unable to get public key from issuer %s for kid %s with error %s", config.Issuer, kid, err)
		}
	}

	//public keys are calculated JIT as they are dynamic
	if err == nil && config.UseDynamicValidation {
		claims = token.Claims.(jwt.MapClaims)

		var issuer string
		if claims["iss"] != nil {
			issuer = claims["iss"].(string)
		} else {
			issuer = ""
		}

		if issuer == "" {
			log.Debugf("Unable to get issuer from JWT so unable to validate kid %s", kid)
		} else {
			//Dynamic validation only works if issuer follows well-known convention for OIDC and doesn't have custom hacks
			//like appending ?p=ProfileName and not including it in the issuer.
			//So allow the primary to specify this and match on the issuer to decide if it should handle request
			//Right thing to do is move them into configuration array, lets hope that there is only one issuer per configuration that has this dodgyness
			if publicKey == nil || issuer != config.Issuer {
				publicKey, _, err = GetPublicKeyFromIssuerUri(kid, issuer)
				if err != nil {
					log.Debugf("Unable to get public key from issuer %s for kid %s with error %s", config.Issuer, kid, err)
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}

	//TODO: Validate for ES256,ES384,ES512?
	return publicKey, nil
}

func createJwtHandler(config *types.Jwt) (negroni.HandlerFunc, error) {
	var err error

	//Redirect url for SSO
	var ssoRedirectUrlTemplate *template.Template
	if config.SsoAddressTemplate != "" {
		ssoRedirectUrlTemplate, err = getSsoRedirectUrlTemplate(config.SsoAddressTemplate)
		if err != nil {
			log.Errorf("Unable to parse config SsoAddressTemplate: %s", err)
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
			log.Errorf("Unable to parse config PublicKey: %s", err)
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
			log.Errorf("Unable to parse config UrlMacPrivateKey: %s", err)
			return nil, err
		}
	} else {
		urlHashPrivateKey = nil
	}

	//Validations
	var algorithmValidationRegex *regexp.Regexp
	if config.AlgorithmValidationRegex != "" {
		algorithmValidationRegex, err = regexp.Compile(config.AlgorithmValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config AlgorithmValidationRegex: %s", err)
			return nil, err
		}
	} else {
		algorithmValidationRegex = nil
	}

	var issuerValidationRegex *regexp.Regexp
	if config.IssuerValidationRegex != "" {
		issuerValidationRegex, err = regexp.Compile(config.IssuerValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config IssuerValidationRegex: %s", err)
			return nil, err
		}
	} else {
		issuerValidationRegex = nil
	}

	var audienceValidationRegex *regexp.Regexp
	if config.AudienceValidationRegex != "" {
		audienceValidationRegex, err = regexp.Compile(config.AudienceValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config AudienceValidationRegex: %s", err)
			return nil, err
		}
	} else {
		audienceValidationRegex = nil
	}

	var subjectValidationRegex *regexp.Regexp
	if config.SubjectValidationRegex != "" {
		subjectValidationRegex, err = regexp.Compile(config.SubjectValidationRegex)
		if err != nil {
			log.Errorf("Unable to parse config AudienceValidationRegex: %s", err)
			return nil, err
		}
	} else {
		subjectValidationRegex = nil
	}

	//Paths to skip OIDC on
	var ignorePathRegex *regexp.Regexp
	if config.IgnorePathRegex != "" {
		ignorePathRegex, err = regexp.Compile(config.IgnorePathRegex)
		if err != nil {
			log.Errorf("Unable to parse config IgnorePathRegex: %s", err)
			return nil, err
		}
	} else {
		ignorePathRegex = nil
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, errorMessage string) {
		if ssoRedirectUrlTemplate == nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(r.URL.Path, redirectorPath) {
			//Drop any pre-existing cookie as it should be dead now
			sessionCookie := getExpiredSessionCookie(r.URL)
			http.SetCookie(w, sessionCookie)

			//Prevent endless loop if callback address, no one should be calling this directly without an id_token set
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
	}

	extractor := func(r *http.Request) (token string, err error) {
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

		//SSO can post to specific url to set token_id (could also be used for forms authentication?)
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, redirectorPath) {
			err = r.ParseForm()
			if err == nil {
				token = r.Form.Get("id_token")
				if token != "" {
					return token, nil
				}
			}
		}

		//For people without javascript
		query := r.URL.Query()
		token = query.Get("id_token")
		if token != "" {
			return token, nil
		}

		return "", nil
	}

	validationKeyGetter := func(token *jwt.Token) (interface{}, error) {
		algHeader, ok := token.Header["alg"]
		if !ok {
			return nil, fmt.Errorf("Cannot get algorithm to use")
		}
		alg := algHeader.(string)

		if algorithmValidationRegex != nil && !algorithmValidationRegex.MatchString(alg) {
			return nil, fmt.Errorf("Jwt token does not match any allowed algorithm type")
		}

		var kid string
		kidHeader, ok := token.Header["kid"]
		if ok {
			kid = kidHeader.(string)
		} else {
			kid = ""
		}

		if clientSecret != nil && kid == "" && (alg == "HS256" || alg == "HS384" || alg == "HS512") {
			return clientSecret, nil
		}

		if publicKey != nil && (kid == "" || (config.Issuer == "" && config.JwksAddress == "" && config.DiscoveryAddress == "" && !config.UseDynamicValidation)) {
			//TODO: Validate for ES256,ES384,ES512?
			return publicKey, nil
		}

		// If kid exists then we using dynamic public keys (oidc)
		if kid != "" && (config.Issuer != "" || config.JwksAddress != "" || config.DiscoveryAddress != "" || config.UseDynamicValidation) {
			return oidcValidationKeyGetter(config, kid, issuerValidationRegex, audienceValidationRegex, subjectValidationRegex, token)
		}

		return nil, fmt.Errorf("Jwt token does not match any allowed algorithm type")
	}

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ErrorHandler: errorHandler,
		Extractor: extractor,
		ValidationKeyGetter: validationKeyGetter,
	})

	jwtHandlerFunc := func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		if ignorePathRegex != nil && ignorePathRegex.MatchString(r.URL.Path) {
			if next != nil {
				next(w, r)
			}
			return
		}

		if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, robotsPath) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "User-agent: *\nDisallow: /")
			return
		}

		err := jwtMiddleware.CheckJWT(w, r)

		if err == nil && r.URL != nil && strings.HasPrefix(r.URL.Path, redirectorPath) {
			// Unauthorized page with javascript to capture id_token from bookmark has run and redirected here
			var redirectUrl *url.URL

			if urlHashPrivateKey != nil {
				redirectUrl, err = getRedirectUrl(r, urlHashPrivateKey)
			} else if urlHashClientSecret != nil {
				redirectUrl, err = getRedirectUrl(r, urlHashClientSecret)
			} else {
				err = fmt.Errorf("No url hash validation private key or url hash client secret is set")
			}

			//Was validated earlier so we know that its a valid value
			token := ""

			//Get id_token from form post
			if r.Method == "POST" && strings.HasPrefix(r.URL.Path, redirectorPath) {
				err = r.ParseForm()
				if err == nil {
					token = r.Form.Get("id_token")
				}
			}

			if token == "" {
				//For people without javascript
				query := r.URL.Query()
				token = query.Get("id_token")
			}

			if token == "" {
				//For people who have it set in a cookie
				sessionCookie, err := r.Cookie(sessionCookieName)
				if err == nil {
					token = sessionCookie.Value
				}
			}

			if token == "" {
				err = fmt.Errorf("Unable to get id_token from form")
			}

			if err == nil && redirectUrl != nil && token != "" {
				log.Infof("provided id_token passed validation, redirecting to: %s", redirectUrl.String())

				sessionCookie := getCookie(r.URL, token)
				http.SetCookie(w, sessionCookie)
				http.Redirect(w, r, redirectUrl.String(), http.StatusSeeOther)
				return
			}

			//More then likely there is something wrong with the validation rules of the issues id_token (issuer could be incorrectly configured)
			log.Infof("provided id_token failed validation: %s", err)

			//Drop any pre-existing cookie as it should be dead now
			sessionCookie := getExpiredSessionCookie(r.URL)
			http.SetCookie(w, sessionCookie)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		// If there was an error, do not call next.
		if err == nil && next != nil {
			next(w, r)
		} else {
			token, _ := extractor(r)

			log.Debugf("JWT Middleware error: url=%s token=%s error=%v", r.URL, token, err)
		}
	}

	return jwtHandlerFunc, nil
}
