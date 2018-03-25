package jwt

import (
	"net/http"
	"net/url"
	"fmt"
)

var callbackPath = "/oauth2/callback"
var redirectorPath = "/oauth2/redirector"
var robotsPath = "/robots.txt"

var redirectUriQuerystringParameterName = "redirect_uri"
var nonceQuerystringParameterName = "Nonce"
var issuedAtQuerystringParameterName = "iat"
var hashQuerystringParameterName = "hash"

var idTokenBookmarkParameterName = "id_token"
var stateBookmarkParameterName = "state"

func cloneUrl(r *http.Request)(*url.URL){
	clonedUrl := &url.URL{
		Scheme: r.URL.Scheme,
		Opaque: r.URL.Opaque,
		User:   r.URL.User,
		Host:   r.URL.Host,
		Path:   r.URL.Path,
	}

	if clonedUrl.Host == "" {
		clonedUrl.Host = r.Host
	}

	if clonedUrl.Scheme == "" {
		if r.TLS != nil {
			clonedUrl.Scheme = "https"
		} else {
			clonedUrl.Scheme = "http"
		}
	}

	return clonedUrl
}

func addMacHashToUrl(url *url.URL, key interface{}) (error) {
	hash, err := SignMac(url.String(), key)
	if err != nil {
		return err
	}
	q := url.Query()
	q.Set(hashQuerystringParameterName, hash)
	url.RawQuery = q.Encode()
	return nil
}

func verifyAndStripMacHashFromUrl(url *url.URL, key interface{})(error){
	query := url.Query()

	signature := query.Get(hashQuerystringParameterName)
	if signature == "" {
		return fmt.Errorf("No %s querystring in uri", hashQuerystringParameterName)
	}

	q := url.Query()
	q.Del(hashQuerystringParameterName)
	url.RawQuery = q.Encode()

	return VerifyMac(url.String(), signature, key)
}

//var redirectUrlTemplate = `https://{{.Host}}/oauth2/redirector?redirect_uri={{.Url}}&Nonce={{.Nonce}}&iat={{.IssuedAt}}&hash={{.Hash}}`
func getRedirectorUrl(r *http.Request, key interface{}, nonce string, issuedAt string) (*url.URL, error) {
	clonedUrl := cloneUrl(r)
	redirectUrl := clonedUrl.String()
	clonedUrl.Path = redirectorPath

	q := clonedUrl.Query()
	q.Set(redirectUriQuerystringParameterName, redirectUrl)
	q.Set(nonceQuerystringParameterName, nonce)
	q.Set(issuedAtQuerystringParameterName, issuedAt)
	clonedUrl.RawQuery = q.Encode()

	err := addMacHashToUrl(clonedUrl, key)
	if err != nil {
		return nil, err
	}

	return clonedUrl, nil
}

func getRedirectUrl(r *http.Request, key interface{}) (*url.URL, error) {
	clonedUrl := cloneUrl(r)

	err := verifyAndStripMacHashFromUrl(clonedUrl, key)
	if err != nil {
		return nil, err
	}

	query := r.URL.Query()

	redirectUriString := query.Get(redirectUriQuerystringParameterName)
	if redirectUriString == "" {
		return nil, fmt.Errorf("No %s querystring in uri", redirectUriQuerystringParameterName)
	}

	nonce := query.Get(nonceQuerystringParameterName)
	if nonce == "" {
		return nil, fmt.Errorf("No %s querystring in uri", nonceQuerystringParameterName)
	}

	issuedAt := query.Get(issuedAtQuerystringParameterName)
	if issuedAt == "" {
		return nil, fmt.Errorf("No %s querystring in uri", issuedAtQuerystringParameterName)
	}

	return url.Parse(redirectUriString)
}
