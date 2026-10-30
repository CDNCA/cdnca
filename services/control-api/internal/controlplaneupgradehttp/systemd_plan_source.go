package controlplaneupgradehttp

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

const (
	SystemdPlanSourcePath         = "/v1/internal/control-upgrade/plan"
	SystemdPlanInstallationHeader = "X-CDNCA-Installation-ID"
	SystemdPlanOperationHeader    = "X-CDNCA-Control-Upgrade-Operation"
)

type SystemdPlanSourceHandler struct {
	repository     controlplaneupgrade.SecretRepository
	installationID string
	operation      string
	token          []byte
	maxBodyBytes   int64
}

func NewSystemdPlanSourceHandler(repository controlplaneupgrade.SecretRepository, installationID,
	operation string, token []byte, maxBodyBytes int64) (*SystemdPlanSourceHandler, error) {
	parsed, err := uuid.Parse(installationID)
	if repository == nil || err != nil || parsed == uuid.Nil || parsed.String() != installationID ||
		operation != controlplaneupgrade.SystemdControlUpgradeOperation || len(token) < 32 || len(token) > 256 ||
		maxBodyBytes < 1 || maxBodyBytes > 2<<20 {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	return &SystemdPlanSourceHandler{repository: repository, installationID: installationID,
		operation: operation, token: append([]byte(nil), token...), maxBodyBytes: maxBodyBytes}, nil
}

func (handler *SystemdPlanSourceHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.Path != SystemdPlanSourcePath || request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !handler.authorized(request) {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	document, err := handler.repository.Read(request.Context())
	if err == nil && document.Publication == nil && len(document.Bundle) == 0 && document.Control == nil {
		response.Header().Set(SystemdPlanInstallationHeader, handler.installationID)
		response.Header().Set(SystemdPlanOperationHeader, handler.operation)
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil || document.Publication == nil || len(document.Bundle) == 0 ||
		int64(len(document.Bundle)) > handler.maxBodyBytes || document.Publication.InstallationID != handler.installationID ||
		document.Publication.Component != "control-api" || document.Publication.PublicationRevision < 1 {
		http.Error(response, "plan unavailable", http.StatusServiceUnavailable)
		return
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(document.Bundle))
	if document.Publication.BundleSHA256 != digest {
		http.Error(response, "plan unavailable", http.StatusServiceUnavailable)
		return
	}
	etag := systemdPlanETag(document.Publication.PublicationRevision, digest)
	response.Header().Set("ETag", etag)
	response.Header().Set(SystemdPlanInstallationHeader, handler.installationID)
	response.Header().Set(SystemdPlanOperationHeader, handler.operation)
	if request.Header.Get("If-None-Match") == etag {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(document.Bundle)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(document.Bundle)
}

func (handler *SystemdPlanSourceHandler) authorized(request *http.Request) bool {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, raw, found := strings.Cut(values[0], " ")
	provided := []byte(raw)
	return found && scheme == "Bearer" && strings.TrimSpace(raw) == raw && len(provided) == len(handler.token) &&
		subtle.ConstantTimeCompare(provided, handler.token) == 1
}

func systemdPlanETag(revision uint64, digest string) string {
	return fmt.Sprintf(`"%d:%s"`, revision, digest)
}
