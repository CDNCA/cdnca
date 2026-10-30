package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	"github.com/google/uuid"
)

var (
	ErrHTTPPlanSourceInvalid     = errors.New("control upgrade HTTP plan source is invalid")
	ErrHTTPPlanSourceUnavailable = errors.New("control upgrade HTTP plan source is unavailable")
	ErrHTTPPlanSourceConflict    = errors.New("control upgrade HTTP plan source binding conflict")
	ErrHTTPPlanNotPublished      = errors.New("no control upgrade plan has been published")
)

type HTTPPlanSourceConfig struct {
	URL            string
	InstallationID string
	Operation      string
	Token          string
	HTTPClient     *http.Client
	Timeout        time.Duration
	MaxBodyBytes   int64
}

type HTTPPlan struct {
	Bundle   []byte
	ETag     string
	Revision uint64
	Digest   string
	Replayed bool
}

type HTTPPlanSource struct {
	url            string
	installationID string
	operation      string
	token          string
	client         *http.Client
	timeout        time.Duration
	maxBodyBytes   int64

	mu     sync.Mutex
	cached *HTTPPlan
}

func NewHTTPPlanSource(config HTTPPlanSourceConfig) (*HTTPPlanSource, error) {
	parsed, err := url.Parse(config.URL)
	installationID, installationErr := uuid.Parse(config.InstallationID)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != controlplaneupgradehttp.SystemdPlanSourcePath ||
		installationErr != nil || installationID == uuid.Nil || installationID.String() != config.InstallationID ||
		config.Operation != controlplaneupgrade.SystemdControlUpgradeOperation || len(config.Token) < 32 ||
		len(config.Token) > 256 || strings.TrimSpace(config.Token) != config.Token {
		return nil, ErrHTTPPlanSourceInvalid
	}
	if address := net.ParseIP(parsed.Hostname()); config.HTTPClient == nil && address != nil &&
		(address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() || address.IsLinkLocalUnicast() ||
			address.IsLinkLocalMulticast()) {
		return nil, ErrHTTPPlanSourceInvalid
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.Timeout < time.Millisecond || config.Timeout > time.Minute || config.MaxBodyBytes < 1 || config.MaxBodyBytes > 2<<20 {
		return nil, ErrHTTPPlanSourceInvalid
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPPlanSource{url: parsed.String(), installationID: config.InstallationID, operation: config.Operation,
		token: config.Token, client: &clientCopy, timeout: config.Timeout, maxBodyBytes: config.MaxBodyBytes}, nil
}

func (source *HTTPPlanSource) Fetch(ctx context.Context) (HTTPPlan, error) {
	source.mu.Lock()
	defer source.mu.Unlock()

	requestContext, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, source.url, nil)
	if err != nil {
		return HTTPPlan{}, ErrHTTPPlanSourceInvalid
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+source.token)
	if source.cached != nil {
		request.Header.Set("If-None-Match", source.cached.ETag)
	}
	response, err := source.client.Do(request)
	if err != nil {
		return HTTPPlan{}, ErrHTTPPlanSourceUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		if source.cached != nil || response.Header.Get("ETag") != "" ||
			len(response.Header.Values(controlplaneupgradehttp.SystemdPlanInstallationHeader)) != 1 ||
			response.Header.Get(controlplaneupgradehttp.SystemdPlanInstallationHeader) != source.installationID ||
			len(response.Header.Values(controlplaneupgradehttp.SystemdPlanOperationHeader)) != 1 ||
			response.Header.Get(controlplaneupgradehttp.SystemdPlanOperationHeader) != source.operation {
			return HTTPPlan{}, ErrHTTPPlanSourceConflict
		}
		return HTTPPlan{}, ErrHTTPPlanNotPublished
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified {
		return HTTPPlan{}, ErrHTTPPlanSourceUnavailable
	}
	etag := response.Header.Get("ETag")
	revision, digest, err := parseHTTPPlanETag(etag)
	if err != nil {
		return HTTPPlan{}, ErrHTTPPlanSourceInvalid
	}
	if response.Header.Get(controlplaneupgradehttp.SystemdPlanInstallationHeader) != source.installationID ||
		response.Header.Get(controlplaneupgradehttp.SystemdPlanOperationHeader) != source.operation {
		return HTTPPlan{}, ErrHTTPPlanSourceConflict
	}
	if response.StatusCode == http.StatusNotModified {
		if source.cached == nil || etag != source.cached.ETag || revision != source.cached.Revision || digest != source.cached.Digest {
			return HTTPPlan{}, ErrHTTPPlanSourceConflict
		}
		result := cloneHTTPPlan(*source.cached)
		result.Replayed = true
		return result, nil
	}
	if response.ContentLength > source.maxBodyBytes {
		return HTTPPlan{}, ErrHTTPPlanSourceInvalid
	}
	bundle, err := io.ReadAll(io.LimitReader(response.Body, source.maxBodyBytes+1))
	if err != nil {
		return HTTPPlan{}, ErrHTTPPlanSourceUnavailable
	}
	if len(bundle) == 0 || int64(len(bundle)) > source.maxBodyBytes || fmt.Sprintf("%x", sha256.Sum256(bundle)) != digest {
		return HTTPPlan{}, ErrHTTPPlanSourceInvalid
	}
	result := HTTPPlan{Bundle: bundle, ETag: etag, Revision: revision, Digest: digest}
	cached := cloneHTTPPlan(result)
	source.cached = &cached
	return cloneHTTPPlan(result), nil
}

func parseHTTPPlanETag(value string) (uint64, string, error) {
	if len(value) < 68 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, "", ErrHTTPPlanSourceInvalid
	}
	revisionText, digest, found := strings.Cut(value[1:len(value)-1], ":")
	revision, err := strconv.ParseUint(revisionText, 10, 64)
	if !found || err != nil || revision < 1 || len(digest) != 64 {
		return 0, "", ErrHTTPPlanSourceInvalid
	}
	for _, character := range digest {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return 0, "", ErrHTTPPlanSourceInvalid
		}
	}
	return revision, digest, nil
}

func cloneHTTPPlan(plan HTTPPlan) HTTPPlan {
	plan.Bundle = append([]byte(nil), plan.Bundle...)
	return plan
}
