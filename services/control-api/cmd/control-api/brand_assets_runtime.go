package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/brandasset"
	"github.com/cdnca/cdnca/services/control-api/internal/brandassethttp"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpageobjectstore"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type brandAssetRuntimeConfig struct {
	Enabled     bool
	ObjectStore errorpageobjectstore.Config
}

func (config *brandAssetRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	*config = brandAssetRuntimeConfig{}
}

func loadBrandAssetRuntimeConfig() (brandAssetRuntimeConfig, error) {
	enabled, err := loadRuntimeBool("BRAND_ASSET_RUNTIME_ENABLED")
	if err != nil || !enabled {
		return brandAssetRuntimeConfig{}, err
	}
	required := func(name string) (string, error) {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}
	endpoint, err := required("BRAND_ASSET_OBJECT_STORE_ENDPOINT")
	if err != nil {
		return brandAssetRuntimeConfig{}, err
	}
	region, err := required("BRAND_ASSET_OBJECT_STORE_REGION")
	if err != nil {
		return brandAssetRuntimeConfig{}, err
	}
	bucket, err := required("BRAND_ASSET_OBJECT_STORE_BUCKET")
	if err != nil {
		return brandAssetRuntimeConfig{}, err
	}
	accessKeyID, err := required("BRAND_ASSET_OBJECT_STORE_ACCESS_KEY_ID")
	if err != nil {
		return brandAssetRuntimeConfig{}, err
	}
	secretAccessKey, err := required("BRAND_ASSET_OBJECT_STORE_SECRET_ACCESS_KEY")
	if err != nil {
		return brandAssetRuntimeConfig{}, err
	}
	prefix := strings.TrimSpace(os.Getenv("BRAND_ASSET_OBJECT_STORE_PREFIX"))
	if prefix == "" {
		prefix = "brand-assets"
	}
	return brandAssetRuntimeConfig{
		Enabled: true,
		ObjectStore: errorpageobjectstore.Config{
			Endpoint: endpoint, Region: region, Bucket: bucket, Prefix: prefix,
			Credentials: errorPageStaticCredentials{
				accessKeyID: accessKeyID, secretAccessKey: secretAccessKey,
				sessionToken: strings.TrimSpace(os.Getenv("BRAND_ASSET_OBJECT_STORE_SESSION_TOKEN")),
			},
			ConnectTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second, RequestTimeout: 30 * time.Second,
			MaxObjectSize: errorpagecontrol.MaxEdgeResourceBytes, MaxAttempts: 3,
		},
	}, nil
}

type brandAssetObjectStore struct {
	store *errorpageobjectstore.Store
}

func (s brandAssetObjectStore) Put(ctx context.Context, scopeID uuid.UUID, logicalKey string, body []byte, mimeType string) (brandasset.ObjectInfo, error) {
	staging := errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: logicalKey + ".staging"}
	object := errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: logicalKey}
	info, err := s.store.PutStaging(ctx, staging, body, mimeType)
	if err != nil {
		return brandasset.ObjectInfo{}, err
	}
	finalized, err := s.store.Finalize(ctx, staging, object, info)
	if err != nil {
		return brandasset.ObjectInfo{}, err
	}
	return brandasset.ObjectInfo{Size: finalized.Size, SHA256: finalized.SHA256, ImmutableToken: finalized.ImmutableToken}, nil
}

func (s brandAssetObjectStore) Delete(ctx context.Context, scopeID uuid.UUID, logicalKey string) error {
	return s.store.Delete(ctx, errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: logicalKey})
}

func (s brandAssetObjectStore) Open(ctx context.Context, scopeID uuid.UUID, logicalKey, token string) (io.ReadCloser, error) {
	return s.store.Open(ctx, errorpagecontrol.ObjectRef{ScopeID: scopeID, LogicalKey: logicalKey}, token)
}

func buildBrandAssetHandlerFactory(pool *pgxpool.Pool, identityService *identity.Service, objects *errorpageobjectstore.Store) (httpapi.MountedHandlerFactory, error) {
	if pool == nil || identityService == nil || !identityService.Configured() || objects == nil {
		return nil, brandasset.ErrInvalidStore
	}
	return func() (http.Handler, error) {
		service, err := brandasset.NewService(pool, audit.New(pool), brandAssetObjectStore{store: objects}, time.Now)
		if err != nil {
			return nil, err
		}
		return brandassethttp.New(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		})
	}, nil
}

// buildThemeHandlerFactory serves PA-17 themes (ADR 0007 §7). Themes live in
// PostgreSQL, so they need no object store; paid official themes check the
// license through guard.
func buildThemeHandlerFactory(pool *pgxpool.Pool, identityService *identity.Service, guard theme.FeatureGuard) (httpapi.MountedHandlerFactory, error) {
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, theme.ErrUnavailable
	}
	return func() (http.Handler, error) {
		service, err := theme.NewService(pool, audit.New(pool), guard, theme.BuiltinCatalog(), time.Now)
		if err != nil {
			return nil, err
		}
		return theme.NewHandler(service, func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), rawSession)
		})
	}, nil
}
