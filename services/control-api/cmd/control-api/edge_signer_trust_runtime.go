package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	"github.com/cdnca/cdnca/services/control-api/internal/edgesignertrustsync"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocationconsumer"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	edgeSignerTrustEnabledEnv  = "EDGE_SIGNER_TRUST_ENABLED"
	edgeSignerTrustURLEnv      = "EDGE_SIGNER_TRUST_URL"
	edgeSignerTrustIntervalEnv = "EDGE_SIGNER_TRUST_REFRESH_INTERVAL"
	edgeSignerTrustDownloads   = "EDGE_SIGNER_TRUST_DOWNLOADS_DIR"
)

type edgeSignerTrustRuntime struct {
	store   *edgesignertrustsync.Store
	fetcher *edgesignertrustsync.Fetcher
	// distributor pushes the latest document to nodes that declared
	// EDGE_SIGNER_TRUST; nil without the edge publication signer or edge NATS.
	distributor *edgesignertrustsync.Distributor
}

func (runtime *edgeSignerTrustRuntime) workers() []runtimeWorker {
	if runtime.distributor == nil {
		return []runtimeWorker{runtime.fetcher}
	}
	return []runtimeWorker{runtime.fetcher, runtime.distributor}
}

// buildEdgeSignerTrustRuntime fetches the offline-root signed node signer
// trust document (签名密钥泄露吊销·节点侧). It is on whenever the offline root
// pin is configured (EDGE_SIGNER_TRUST_ENABLED=false turns it off) and needs
// no other secret: the document carries its own signature. Distribution to
// nodes needs the edge publication signer (nodes verify the bundle with the
// same artifact trust as deployments) and edge NATS (the streams are
// agent-gateway's); without them the documents are still stored and
// published to the downloads directory, and a warning is logged.
func buildEdgeSignerTrustRuntime(pool *pgxpool.Pool, licenseServiceURL string, signer *edgePublishArtifactSigner,
	connection natsRuntimeConnection,
) (*edgeSignerTrustRuntime, error) {
	enabled := os.Getenv(edgeSignerTrustEnabledEnv)
	if enabled != "" && enabled != "true" && enabled != "false" {
		return nil, fmt.Errorf("%s must be true or false", edgeSignerTrustEnabledEnv)
	}
	root, configured, err := signerrevocationconsumer.LoadOfflineRoot()
	if err != nil {
		return nil, err
	}
	if enabled == "false" || (!configured && enabled == "") {
		return nil, nil
	}
	if !configured {
		return nil, errors.New(edgeSignerTrustEnabledEnv + "=true requires SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_*")
	}
	documentURL := os.Getenv(edgeSignerTrustURLEnv)
	if documentURL == "" {
		if documentURL, err = edgesignertrustsync.DocumentURL(licenseServiceURL); err != nil {
			return nil, fmt.Errorf("%s is unset and LICENSE_SERVICE_URL: %w", edgeSignerTrustURLEnv, err)
		}
	}
	interval := 10 * time.Minute
	if raw := os.Getenv(edgeSignerTrustIntervalEnv); raw != "" {
		if interval, err = time.ParseDuration(raw); err != nil || interval < time.Minute || interval > 24*time.Hour {
			return nil, fmt.Errorf("%s must be within 1m..24h", edgeSignerTrustIntervalEnv)
		}
	}
	tlsConfig, err := signerrevocationconsumer.TLSConfigFromEnv()
	if err != nil {
		return nil, err
	}
	store, err := edgesignertrustsync.NewStore(pool, []edgesignertrust.RootPin{{KeyID: root.KeyID,
		Generation: root.Generation, PublicKey: root.PublicKey}}, time.Now)
	if err != nil {
		return nil, err
	}
	downloads := os.Getenv(edgeSignerTrustDownloads)
	if downloads != "" && (!filepath.IsAbs(downloads) || filepath.Clean(downloads) != downloads) {
		return nil, fmt.Errorf("%s must be an absolute clean path", edgeSignerTrustDownloads)
	}
	runtime := &edgeSignerTrustRuntime{store: store}
	edgeNATS, _ := connection.(*nats.Conn)
	if signer != nil && edgeNATS != nil {
		transport, err := edgesignertrustsync.NewNATSTransport(edgeNATS, 5*time.Second)
		if err != nil {
			return nil, err
		}
		if runtime.distributor, err = edgesignertrustsync.NewDistributor(edgesignertrustsync.DistributorConfig{
			Store: store, Nodes: edgesignertrustsync.ActiveNodes(pool), Transport: transport, KeyID: signer.KeyID(),
			Sign: signer.Sign, Interval: time.Minute, Logger: slog.Default()}); err != nil {
			return nil, err
		}
	} else {
		slog.Warn("edge signer trust is not pushed to nodes: the edge publication signer or edge NATS is not configured")
	}
	var onAccepted func()
	if runtime.distributor != nil {
		onAccepted = runtime.distributor.Wake
	}
	runtime.fetcher, err = edgesignertrustsync.NewFetcher(edgesignertrustsync.FetcherConfig{URL: documentURL,
		TLSConfig: tlsConfig, Interval: interval, Timeout: 15 * time.Second, Store: store, Logger: slog.Default(),
		DownloadsDir: downloads, OnAccepted: onAccepted})
	if err != nil {
		return nil, err
	}
	return runtime, nil
}
