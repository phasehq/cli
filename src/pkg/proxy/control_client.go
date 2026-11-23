package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ControlClient returns the HTTP client for the control API of the Phase AI
// proxy at rawProxyURL: every request it sends goes to that proxy, which
// answers the reserved host itself. The URL is one a runtime hands out, plain
// http to a loopback address with the proxy capability as its password.
// Control calls use the main capability whichever Connection the URL selects,
// so they do not depend on that Connection. dialTimeout bounds the connection
// to the proxy, timeout each call.
//
// It is the one constructor for that client: status, the hook runtime and
// leak protection registration all reach the proxy through it.
func ControlClient(rawProxyURL string, dialTimeout, timeout time.Duration) (*http.Client, error) {
	parsed, err := url.Parse(rawProxyURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User == nil {
		return nil, errors.New("Phase proxy URL is invalid")
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Phase proxy URL is invalid")
	}
	password, present := parsed.User.Password()
	if !ValidProxyUsername(parsed.User.Username()) || !present || password == "" {
		return nil, errors.New("Phase proxy authentication is unavailable")
	}
	if !IsLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("managed Phase proxy is not bound to loopback")
	}
	parsed.User = url.UserPassword("phase", password)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(parsed)
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout}).DialContext
	return &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
