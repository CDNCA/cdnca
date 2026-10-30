package safedefault

import (
	"net/http"
	"time"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	http HTTPClient
}

func NewClient(httpClient HTTPClient) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{http: httpClient}
}
