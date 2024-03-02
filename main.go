package authredirect

import (
	"bytes"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-resty/resty/v2"
	"io"
	"net/http"
	"time"
)

func init() {
	caddy.RegisterModule(AuthRedirect{})
	httpcaddyfile.RegisterHandlerDirective("auth_redirect", parseCaddyfile)
}

type AuthRedirect struct {
	Url string `json:"url"`

	restyClient *resty.Client
}

func (AuthRedirect) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.auth_redirect",
		New: func() caddy.Module { return new(AuthRedirect) },
	}
}

func (f *AuthRedirect) Provision(c caddy.Context) error {
	f.restyClient = resty.New()
	f.restyClient.SetTimeout(8 * time.Second)
	f.restyClient.SetRedirectPolicy(resty.NoRedirectPolicy())

	c.Logger(f).Info(fmt.Sprintf("AuthRedirect: %s", f.Url))

	return nil
}

func (f AuthRedirect) ServeHTTP(w http.ResponseWriter, clientReq *http.Request, next caddyhttp.Handler) error {
	authReqHeaders := map[string]string{}
	for k, v := range clientReq.Header {
		for _, v2 := range v {
			authReqHeaders[k] = v2
		}
	}

	var resp *resty.Response
	var err error
	urlParameters := clientReq.URL.Query().Encode()
	if clientReq.Method == http.MethodPost {
		buf := new(bytes.Buffer)
		_, _ = io.Copy(buf, clientReq.Body)
		clientReq.Body = io.NopCloser(buf)

		resp, err = f.restyClient.R().SetHeaders(authReqHeaders).SetBody(buf.Bytes()).Post(f.Url + "?" + urlParameters)
	} else {
		resp, err = f.restyClient.R().SetHeaders(authReqHeaders).Get(f.Url + "?" + urlParameters)
	}

	if err != nil {
		return err
	}

	respStatusCode := resp.StatusCode()
	if respStatusCode == http.StatusOK {
		return next.ServeHTTP(w, clientReq)
	}

	for k, v := range resp.Header() {
		for _, v2 := range v {
			w.Header().Set(k, v2)
		}
	}

	w.WriteHeader(respStatusCode)
	_, _ = w.Write(resp.Body())
	if err != nil {
		return err
	}
	return nil
}

func (f *AuthRedirect) Validate() error {
	if f.Url == "" {
		return fmt.Errorf("auth_redirect <url> not specified")
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var f AuthRedirect
	err := f.UnmarshalCaddyfile(h.Dispenser)

	return f, err
}

func (f *AuthRedirect) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&f.Url) {
			return d.ArgErr()
		}
	}
	return nil
}

var (
	_ caddy.Validator             = (*AuthRedirect)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthRedirect)(nil)
	_ caddy.Provisioner           = (*AuthRedirect)(nil)
)
