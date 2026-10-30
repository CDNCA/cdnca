package edgesignertrustsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
)

// Transport carries bundles to agent-gateway and receipts back.
type Transport interface {
	PublishBundle(ctx context.Context, nodeID string, revision uint64, encoded []byte) error
	// NextReceipt waits up to the transport's poll timeout; (nil, nil) when nothing arrived.
	NextReceipt(ctx context.Context) (ReceiptDelivery, error)
}

type ReceiptDelivery interface {
	NodeID() string
	ReceiptJSON() []byte
	Ack(context.Context) error
	Nak(context.Context) error
}

// DistributionStore is what the distributor needs of Store.
type DistributionStore interface {
	Latest(ctx context.Context) (Accepted, bool, error)
	EnforcedRevisions(ctx context.Context) (map[string]uint64, error)
	RecordReceipt(ctx context.Context, receipt edgesignertrust.Receipt) error
}

type DistributorConfig struct {
	Store DistributionStore
	// Nodes lists the active nodes (ActiveNodes in production). Only nodes
	// that declared CAPABILITY_NAME_EDGE_SIGNER_TRUST get a bundle; the others
	// are logged and picked up once an upgraded Agent declares it.
	Nodes     func(context.Context) ([]NodeTarget, error)
	Transport Transport
	KeyID     string
	Sign      func(context.Context, []byte) ([]byte, error)
	Interval  time.Duration
	// RetryAfter delays republishing to a node that rejected or never answered (default 10 minutes).
	RetryAfter time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
}

// Distributor publishes the latest accepted document to every active node
// until the node reports it enforces that revision. The gateway keeps only
// the newest bundle per node, so an offline node converges when it connects.
type Distributor struct {
	config    DistributorConfig
	wake      chan struct{}
	mu        sync.Mutex
	published map[string]publishedBundle
	lastError string
	// lastIncapable is the logged set of nodes without the capability.
	lastIncapable string
	onApplied     func()
}

// OnApplied registers a call after a node reports it applied a document (the
// installation ban distributor waits for it). Set before Run.
func (distributor *Distributor) OnApplied(callback func()) {
	distributor.onApplied = callback
}

type publishedBundle struct {
	revision uint64
	at       time.Time
}

func NewDistributor(config DistributorConfig) (*Distributor, error) {
	if config.Store == nil || config.Nodes == nil || config.Transport == nil || config.KeyID == "" ||
		config.Sign == nil || config.Interval <= 0 {
		return nil, errors.New("edge signer trust distributor configuration is incomplete")
	}
	if config.RetryAfter <= 0 {
		config.RetryAfter = 10 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Distributor{config: config, wake: make(chan struct{}, 1), published: map[string]publishedBundle{}}, nil
}

// Wake runs a publication pass soon (a new revision was accepted).
func (distributor *Distributor) Wake() {
	select {
	case distributor.wake <- struct{}{}:
	default:
	}
}

func (distributor *Distributor) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		distributor.consumeReceipts(ctx)
	}()
	ticker := time.NewTicker(distributor.config.Interval)
	defer ticker.Stop()
	for {
		distributor.report(distributor.PublishOnce(ctx))
		select {
		case <-ctx.Done():
			<-done
			return ctx.Err()
		case <-ticker.C:
		case <-distributor.wake:
		}
	}
}

// PublishOnce publishes the latest document to every node that does not
// enforce it yet and has no recent publication of it.
func (distributor *Distributor) PublishOnce(ctx context.Context) error {
	latest, found, err := distributor.config.Store.Latest(ctx)
	if err != nil || !found {
		return err
	}
	nodes, err := distributor.config.Nodes(ctx)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	enforced, err := distributor.config.Store.EnforcedRevisions(ctx)
	if err != nil {
		return fmt.Errorf("read node signer trust state: %w", err)
	}
	now := distributor.config.Now()
	var failure error
	incapable := []string{}
	for _, node := range nodes {
		nodeID := node.ID
		if enforced[nodeID] >= latest.Revision {
			continue
		}
		if !node.Capable {
			incapable = append(incapable, nodeID)
			continue
		}
		distributor.mu.Lock()
		previous, sent := distributor.published[nodeID]
		recent := sent && previous.revision == latest.Revision && now.Before(previous.at.Add(distributor.config.RetryAfter))
		distributor.mu.Unlock()
		if recent {
			continue
		}
		encoded, err := distributor.bundle(ctx, nodeID, latest.Document, now)
		if err == nil {
			err = distributor.config.Transport.PublishBundle(ctx, nodeID, latest.Revision, encoded)
		}
		if err != nil {
			failure = errors.Join(failure, fmt.Errorf("publish edge signer trust to %s: %w", nodeID, err))
			continue
		}
		distributor.mu.Lock()
		distributor.published[nodeID] = publishedBundle{revision: latest.Revision, at: now}
		distributor.mu.Unlock()
		distributor.config.Logger.Info("edge signer trust published", "node_id", nodeID, "revision", latest.Revision)
	}
	distributor.reportIncapable(latest.Revision, incapable)
	return failure
}

// reportIncapable logs, once per change, the nodes that cannot receive the
// latest revision because their Agent does not declare EDGE_SIGNER_TRUST.
func (distributor *Distributor) reportIncapable(revision uint64, nodes []string) {
	key := fmt.Sprint(revision, nodes)
	distributor.mu.Lock()
	changed := key != distributor.lastIncapable
	distributor.lastIncapable = key
	distributor.mu.Unlock()
	if !changed || len(nodes) == 0 {
		return
	}
	shown := nodes
	if len(shown) > 20 {
		shown = shown[:20]
	}
	distributor.config.Logger.Warn("edge signer trust not delivered: node agent lacks EDGE_SIGNER_TRUST (upgrade the node)",
		"revision", revision, "nodes", len(nodes), "node_ids", shown)
}

func (distributor *Distributor) bundle(ctx context.Context, nodeID string, document []byte, now time.Time) ([]byte, error) {
	bundle, err := edgesignertrust.NewBundle(nodeID, document, distributor.config.KeyID, now)
	if err != nil {
		return nil, err
	}
	payload, err := edgesignertrust.BundleSigningPayload(bundle)
	if err != nil {
		return nil, err
	}
	signature, err := distributor.config.Sign(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("sign edge signer trust bundle: %w", err)
	}
	return edgesignertrust.SealBundle(bundle, signature)
}

func (distributor *Distributor) consumeReceipts(ctx context.Context) {
	for ctx.Err() == nil {
		delivery, err := distributor.config.Transport.NextReceipt(ctx)
		if err != nil {
			if ctx.Err() == nil {
				distributor.config.Logger.Warn("edge signer trust receipts unavailable", "error", err)
				select {
				case <-ctx.Done():
				case <-time.After(distributor.config.Interval):
				}
			}
			continue
		}
		if delivery != nil {
			distributor.HandleReceipt(ctx, delivery)
		}
	}
}

// HandleReceipt records one node receipt.
func (distributor *Distributor) HandleReceipt(ctx context.Context, delivery ReceiptDelivery) {
	receipt, err := edgesignertrust.DecodeReceipt(delivery.ReceiptJSON())
	if err != nil || receipt.NodeID != delivery.NodeID() {
		distributor.config.Logger.Warn("edge signer trust receipt dropped", "node_id", delivery.NodeID())
		_ = delivery.Ack(ctx)
		return
	}
	if err := distributor.config.Store.RecordReceipt(ctx, receipt); err != nil {
		distributor.config.Logger.Warn("edge signer trust receipt not recorded yet", "node_id", receipt.NodeID, "error", err)
		_ = delivery.Nak(ctx)
		return
	}
	level := slog.LevelInfo
	if receipt.Result != edgesignertrust.ResultApplied {
		level = slog.LevelWarn
	}
	distributor.config.Logger.Log(ctx, level, "edge signer trust receipt", "node_id", receipt.NodeID,
		"enforced_revision", receipt.Revision, "result", receipt.Result, "reason", receipt.Reason)
	_ = delivery.Ack(ctx)
	if receipt.Result == edgesignertrust.ResultApplied && distributor.onApplied != nil {
		distributor.onApplied()
	}
}

func (distributor *Distributor) report(err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	if message != distributor.lastError {
		if err != nil {
			distributor.config.Logger.Warn("edge signer trust publication pass failed", "error", err)
		} else if distributor.lastError != "" {
			distributor.config.Logger.Info("edge signer trust publication recovered")
		}
		distributor.lastError = message
	}
}
