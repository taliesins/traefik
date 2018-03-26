package jwt

import (
	"bytes"
	"net/url"
	"strings"
	"text/template"
	htmlTemplate "text/template"
)

var sessionCookieName = "id_token"

type ssoRedirectUrlTemplateOptions struct {
	CallbackUrl string
	State       string
	Nonce       string
	IssuedAt    string
}

//"https://login.microsoftonline.com/traefik_k8s_test.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=1234f2b2-9fe3-1234-11a6-f123e76e3843&nonce={{.Nonce}}&redirect_uri={{.Url}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login"
func getSsoRedirectUrlTemplate(templateToRender string) (*template.Template, error) {
	return template.New("SsoRedirectUrl").Parse(templateToRender)
}

//var redirectUrlTemplate = `https://login.microsoftonline.com/traefik_k8s_test.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_signup_signin&client_id=1234f2b2-9fe3-1234-11a6-f123e76e3843&nonce={{.Nonce}}&redirect_uri={{.CallbackUrl}}&state={{.State}}&scope=openid&response_type=id_token&prompt=login`
func renderSsoRedirectUrlTemplate(ssoRedirectUrlTemplate *template.Template, urlToRedirectTo *url.URL, nonce string, issuedAt string) (*url.URL, error) {
	//We want to only use a hard coded host and path in the callback page. The hash ensures that the correct full path is required when doing a redirect. This also reduces the size of the state querystring parameter
	encodedUrl := urlToRedirectTo.Query().Encode()
	callbackUrl, err := url.Parse(urlToRedirectTo.String())
	if err != nil {
		return nil, err
	}

	callbackUrl.RawQuery = ""
	callbackUrl.Path = callbackPath

	var redirectSsoUrlTemplateRendered bytes.Buffer
	err = ssoRedirectUrlTemplate.Execute(&redirectSsoUrlTemplateRendered, ssoRedirectUrlTemplateOptions{
		CallbackUrl: callbackUrl.String(),
		State:       encodedUrl,
		Nonce:       nonce,
		IssuedAt:    issuedAt,
	})

	if err != nil {
		return nil, err
	}

	ssoRedirectUrl, err := url.Parse(redirectSsoUrlTemplateRendered.String())
	if err != nil {
		return nil, err
	}

	return ssoRedirectUrl, nil
}

type redirectToSsoPageTemplateOptions struct {
	RedirectUrl  *url.URL
	ErrorMessage string
}

var attributeReplacer = strings.NewReplacer(
	string(0), "\uFFFD",
	"\"", "&#34;",
	"'", "&#39;",
	"+", "&#43;",
	"<", "&lt;",
	">", "&gt;",
)

var redirectToSsoPageTemplate = template.Must(template.New("RedirectToSsoPage").Funcs(template.FuncMap{
	"escapeJavascriptVariable": func(textToEscape *url.URL) string {
		return htmlTemplate.JSEscapeString(textToEscape.String())
	},
	"escapeHtml": func(textToEscape *url.URL) string {
		return htmlTemplate.HTMLEscapeString(textToEscape.String())
	},
	"escapeAttribute": func(textToEscape *url.URL) string {
		return attributeReplacer.Replace(textToEscape.String())
	},
}).Parse(`
<!DOCTYPE html><html><head><title></title></head><body>
{{.ErrorMessage}}
<script>
window.location = '{{ .RedirectUrl | escapeJavascriptVariable }}'
</script>
Please sign in at <a href='{{.RedirectUrl | escapeAttribute}}'>{{ .RedirectUrl | escapeHtml}}</a>
</body></html>
`))

func renderRedirectToSsoPageTemplate(redirectUrl *url.URL, errorMessage string) (string, error) {
	var redirectToSingleSignOnTemplateRendered bytes.Buffer
	err := redirectToSsoPageTemplate.Execute(&redirectToSingleSignOnTemplateRendered, redirectToSsoPageTemplateOptions{
		RedirectUrl:  redirectUrl,
		ErrorMessage: errorMessage,
	})

	if err != nil {
		return "", err
	}

	return redirectToSingleSignOnTemplateRendered.String(), nil
}

type ssoCallbackPageTemplateOptions struct {
	RedirectorUrl                string
	SessionCookieName            string
	IdTokenBookmarkParameterName string
	StateBookmarkParameterName   string
}

var ssoCallbackPageTemplate = template.Must(template.New("SsoCallbackPage").Funcs(template.FuncMap{
	"escapeJavascriptVariable": func(textToEscape string) string {
		return htmlTemplate.JSEscapeString(textToEscape)
	},
}).Parse(`
<!DOCTYPE html><html><head><title></title></head><body>
<script>
function getBookMarkParameterByName(name, url) {
    if (!url) url = window.location.hash;
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[#&?]" + name + "(=([^&#]*)|&|#|$)"), results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}

state = encodeURIComponent(getBookMarkParameterByName('{{ escapeJavascriptVariable .StateBookmarkParameterName}}'));
window.location.replace();
if (state) {
	document.cookie = '{{ escapeJavascriptVariable .SessionCookieName}}=' + getBookMarkParameterByName('{{ escapeJavascriptVariable .IdTokenBookmarkParameterName}}');
	window.location = '{{ escapeJavascriptVariable .RedirectorUrl}}?' + state;
}
</script>
Please change the '#' in the url to '&' and goto link
</body></html>
`))

func renderSsoCallbackPageTemplate(redirectorUrl *url.URL) (string, error) {
	redirectorUrlWithoutQuerystring, err := url.Parse(redirectorUrl.String())
	if err != nil {
		return "", err
	}

	//Strip querystring as this is coming from the state parameter
	redirectorUrlWithoutQuerystring.RawQuery = ""

	var idTokenInBookmarkRedirectPageTemplateRendered bytes.Buffer
	err = ssoCallbackPageTemplate.Execute(&idTokenInBookmarkRedirectPageTemplateRendered, ssoCallbackPageTemplateOptions{
		RedirectorUrl:                redirectorUrlWithoutQuerystring.String(),
		SessionCookieName:            sessionCookieName,
		IdTokenBookmarkParameterName: idTokenBookmarkParameterName,
		StateBookmarkParameterName:   stateBookmarkParameterName,
	})

	if err != nil {
		return "", err
	}

	return idTokenInBookmarkRedirectPageTemplateRendered.String(), nil
}
