package jwt

import (
	"bytes"
	"net/url"
	"text/template"
	"net/http"
)

var sessionCookieName = "traefik_session"
var redirectUriQuerystringParameterName = "redirect_uri"
var idTokenBookmarkParameterName = "id_token"
var callbackPath = "/traefik/oauth2/callback"

//var redirectUrlTemplate = `https://{{.Host}}/traefik/oauth2/callback?redirect_uri={{.Url}}`
func renderCallbackRedirectUrlTemplate(r *http.Request, callbackPath string, redirectUriQuerystringParameterName string) (string, error) {
	urlClone := &url.URL{
		Scheme: r.URL.Scheme,
		Opaque: r.URL.Opaque,
		User: r.URL.User,
		Host: r.URL.Host,
		Path: r.URL.Path,
	}

	if urlClone.Host == ""{
		urlClone.Host = r.Host
	}

	if urlClone.Scheme == "" {
		if r.TLS != nil {
			urlClone.Scheme =  "https"
		} else {
			urlClone.Scheme =  "http"
		}
	}

	redirectUrl := urlClone.String()

	urlClone.Path = callbackPath

	q := urlClone.Query()
	q.Set(redirectUriQuerystringParameterName, redirectUrl)
	urlClone.RawQuery = q.Encode()

	return urlClone.String(), nil
}

type ssoRedirectUrlTemplateOptions struct {
	Url string
}

func getSsoRedirectUrlTemplate(templateToRender string) (*template.Template, error) {
	return template.New("SsoRedirectUrl").Parse(templateToRender)
}

//var redirectUrlTemplate = `https://login.microsoftonline.com/traefik_k8s_test.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=1234f2b2-9fe3-1234-11a6-f123e76e3843&nonce=defaultNonce&redirect_uri={{.Url}}&scope=openid&response_type=id_token&prompt=login`
func renderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate *template.Template, urlToRedirectTo string) (string, error) {
	encodedUrl := url.QueryEscape(urlToRedirectTo)

	var redirectSsoUrlTemplateRendered bytes.Buffer
	err := ssoRedirectUrlTemplate.Execute(&redirectSsoUrlTemplateRendered, ssoRedirectUrlTemplateOptions{
		Url: encodedUrl,
	})

	if err != nil {
		return "", err
	}

	return string(redirectSsoUrlTemplateRendered.Bytes()), nil
}

type redirectToSsoPageTemplateOptions struct {
	RedirectUrl  string
	ErrorMessage string
}

var redirectToSsoPageTemplate = template.Must(template.New("RedirectToSsoPage").Parse(`
<html><body>
{{.ErrorMessage}}
<javascript>
window.location = '{{.RedirectUrl}}'
</javascript>
<noscript>
Please sign in at {{.RedirectUrl}}
</noscript>
</body></html>
`))

func renderRedirectToSsoPageTemplate(redirectUrl string, errorMessage string) (string, error) {
	var redirectToSingleSignOnTemplateRendered bytes.Buffer
	err := redirectToSsoPageTemplate.Execute(&redirectToSingleSignOnTemplateRendered, redirectToSsoPageTemplateOptions{
		RedirectUrl:  redirectUrl,
		ErrorMessage: errorMessage,
	})

	if err != nil {
		return "", err
	}

	return string(redirectToSingleSignOnTemplateRendered.Bytes()), nil
}

type idTokenInBookmarkRedirectPageTemplateOptions struct {
	SessionCookieName            string //
	RedirectUrl                  string
	IdTokenBookmarkParameterName string //id_token
}

var idTokenInBookmarkRedirectTemplate = template.Must(template.New("IdTokenInBookmarkRedirectPage").Parse(`
<html><body>
<javascript>
function getBookMarkParameterByName(name, url) {
    if (!url) url = window.location.hash;
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[#&?]" + name + "(=([^&#]*)|&|#|$)"), results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}

document.cookie = "{{.SessionCookieName}}=" + getBookMarkParameterByName('{{.IdTokenBookmarkParameterName}}') 
window.location = '{{.RedirectUrl}}'
</javascript>
<noscript>
Please change the '#' in the url to '&' and goto link
</noscript>
</body></html>
`))

func renderIdTokenInBookmarkRedirectPageTemplate(redirectUrl string, sessionCookieName string, idTokenBookmarkParameterName string) (string, error) {
	var idTokenInBookmarkRedirectPageTemplateRendered bytes.Buffer
	err := idTokenInBookmarkRedirectTemplate.Execute(&idTokenInBookmarkRedirectPageTemplateRendered, idTokenInBookmarkRedirectPageTemplateOptions{
		RedirectUrl:                  redirectUrl,
		SessionCookieName:            sessionCookieName,
		IdTokenBookmarkParameterName: idTokenBookmarkParameterName,
	})

	if err != nil {
		return "", err
	}

	return string(idTokenInBookmarkRedirectPageTemplateRendered.Bytes()), nil
}
