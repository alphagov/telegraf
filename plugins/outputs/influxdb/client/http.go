package client

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/valyala/fasthttp"
)

func NewHTTP(config HTTPConfig) Client {
	return &httpClient{
		writeURL: []byte(writeURL(config.BaseURL, config.WriteParams)),
		config:   config,
		client: &fasthttp.Client{
			TLSConfig: config.TLSConfig,
		},
	}
}

type HTTPConfig struct {
	BaseURL   string
	UserAgent string
	Timeout   time.Duration
	Username  string
	Password  string
	TLSConfig *tls.Config

	// Default write params
	WriteParams HTTPWriteParams

	Gzip bool
}

type HTTPWriteParams struct {
	Database        string
	RetentionPolicy string
	Precision       string
	Consistency     string
}

type httpClient struct {
	writeURL []byte
	config   HTTPConfig
	client   *fasthttp.Client
}

func (c *httpClient) Query(command string) error {
	req := c.makeRequest()
	req.Header.SetRequestURI(queryURL(c.config.BaseURL, command))
	resp := fasthttp.AcquireResponse()

	err := c.client.DoTimeout(req, resp, c.config.Timeout)
	code := resp.StatusCode()
	if code != 200 && err == nil {
		err = fmt.Errorf("Received bad status code [%d], expected [200]", code)
	}

	fasthttp.ReleaseResponse(resp)
	fasthttp.ReleaseRequest(req)

	return err
}

func (c *httpClient) Write(b []byte) (int, error) {
	req := c.makeRequest()
	req.Header.SetContentLength(len(b))
	req.Header.SetRequestURIBytes(c.writeURL)
	if c.config.Gzip {
		req.Header.SetBytesKV([]byte("Content-Encoding"), []byte("gzip"))
	}
	req.SetBody(b)
	resp := fasthttp.AcquireResponse()

	err := c.client.DoTimeout(req, resp, c.config.Timeout)
	code := resp.StatusCode()
	if code != 204 && err == nil {
		err = fmt.Errorf("Received bad status code [%d], expected [204]", code)
	}

	fasthttp.ReleaseResponse(resp)
	fasthttp.ReleaseRequest(req)

	if err == nil {
		return len(b), nil
	}
	return 0, err
}

func (c *httpClient) WriteStream(b io.Reader, size int) (int, error) {
	req := c.makeRequest()
	req.Header.SetContentLength(size)
	req.Header.SetRequestURIBytes(c.writeURL)
	if c.config.Gzip {
		req.Header.SetBytesKV([]byte("Content-Encoding"), []byte("gzip"))
	}
	req.SetBodyStream(b, size)
	resp := fasthttp.AcquireResponse()

	err := c.client.DoTimeout(req, resp, c.config.Timeout)
	code := resp.StatusCode()
	if code != 204 && err == nil {
		err = fmt.Errorf("Received bad status code [%d], expected [204]", code)
	}

	fasthttp.ReleaseResponse(resp)
	fasthttp.ReleaseRequest(req)

	if err == nil {
		return size, nil
	}
	return 0, err
}

func (c *httpClient) Close() error {
	// Nothing to do.
	return nil
}

func (c *httpClient) makeRequest() *fasthttp.Request {
	req := fasthttp.AcquireRequest()
	req.Header.SetContentTypeBytes([]byte("text/plain"))
	req.Header.SetMethodBytes([]byte("POST"))
	req.Header.SetUserAgent(c.config.UserAgent)
	if c.config.Username != "" && c.config.Password != "" {
		req.Header.Set("Authorization", "Basic "+basicAuth(c.config.Username, c.config.Password))
	}
	return req
}

func writeURL(baseURL string, wp HTTPWriteParams) string {
	params := url.Values{}
	params.Set("db", wp.Database)
	if wp.RetentionPolicy != "" {
		params.Set("rp", wp.RetentionPolicy)
	}
	if wp.Precision != "n" && wp.Precision != "" {
		params.Set("precision", wp.Precision)
	}
	if wp.Consistency != "one" && wp.Consistency != "" {
		params.Set("consistency", wp.Consistency)
	}

	return baseURL + "/write?" + params.Encode()
}

func queryURL(baseURL, command string) string {
	params := url.Values{}
	params.Set("q", command)

	return baseURL + "/query?" + params.Encode()
}

// See 2 (end of page 4) http://www.ietf.org/rfc/rfc2617.txt
// "To receive authorization, the httpClient sends the userid and password,
// separated by a single colon (":") character, within a base64
// encoded string in the credentials."
// It is not meant to be urlencoded.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
