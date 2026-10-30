package artifactsync

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
)

// CatalogClient is the license service side (Client).
type CatalogClient interface {
	Resolve(context.Context, uuid.UUID, string, *artifactcatalog.Head, ed25519.PrivateKey, time.Time) (artifactcatalog.ResolveResponse, error)
	Fetch(context.Context, uuid.UUID, artifactcatalog.Entry, ed25519.PrivateKey, time.Time) ([]byte, error)
}

// EncryptionKeyRegistrar is implemented by a CatalogClient that can register
// the installation encryption key (Client). The syncer registers the key it
// holds before its first resolve of a process, so the license service wraps
// encrypted packs to it.
type EncryptionKeyRegistrar interface {
	RegisterEncryptionKey(context.Context, uuid.UUID, []byte, ed25519.PrivateKey, time.Time) (artifactcatalog.RegisterEncryptionKeyResponse, error)
}

type KeysetRefresher interface {
	Refresh(context.Context) error
}

type SyncerConfig struct {
	Client         CatalogClient
	Store          *Store
	Trust          artifactcatalog.Verifier
	Keysets        KeysetRefresher
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	// EncryptionKey is the raw X25519 installation encryption key (PA-14):
	// it opens the wrapped content keys of encrypted rule packs. Nil: such
	// packs are rejected (rule.pack.decrypt_reject) and never stored.
	EncryptionKey  []byte
	ControlVersion string
	Interval       time.Duration
	// OnChanged runs after a round that changed the usable local artifacts
	// (a download stored, a system rule materialized or withdrawn).
	OnChanged func(context.Context)
	Now       func() time.Time
	Logger    *slog.Logger
}

// Syncer polls the license service. On any failure what was applied and
// downloaded before stays in place; expiry of the catalog never clears it.
type Syncer struct {
	config     SyncerConfig
	registered bool // the encryption key was registered by this process
}

func NewSyncer(config SyncerConfig) (*Syncer, error) {
	if config.Client == nil || config.Store == nil || config.Trust == nil || config.InstallationID == uuid.Nil ||
		len(config.PrivateKey) != ed25519.PrivateKeySize || config.ControlVersion == "" {
		return nil, errors.New("invalid artifact sync configuration")
	}
	if config.Interval <= 0 {
		config.Interval = time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	config.PrivateKey = append(ed25519.PrivateKey(nil), config.PrivateKey...)
	config.EncryptionKey = append([]byte(nil), config.EncryptionKey...)
	return &Syncer{config: config}, nil
}

func (syncer *Syncer) Run(ctx context.Context) error {
	wait, failures := time.Duration(0), 0
	for {
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if err := syncer.SyncOnce(ctx); err != nil && ctx.Err() == nil {
			failures++
			wait = min(time.Duration(1<<min(failures, 8))*5*time.Second, 15*time.Minute)
			syncer.config.Logger.Warn("artifact sync deferred; keeping the last verified catalog and downloads", "error", err)
			continue
		}
		failures, wait = 0, syncer.config.Interval
	}
}

// SyncOnce is one round: resolve and apply the catalog, download what is
// pending, materialize the system rules. A rejected delivery or download is
// recorded and does not stop the round; transport failures return an error
// so Run backs off.
func (syncer *Syncer) SyncOnce(ctx context.Context) error {
	config := syncer.config
	keysetFailed := config.Keysets != nil && config.Keysets.Refresh(ctx) != nil
	if err := syncer.registerEncryptionKey(ctx); err != nil {
		// Encrypted packs wait; everything else syncs as before.
		config.Logger.Warn("installation encryption key registration deferred", "error", err)
	}
	head, err := config.Store.Head(ctx)
	if err != nil {
		return err
	}
	response, err := config.Client.Resolve(ctx, config.InstallationID, config.ControlVersion, head, config.PrivateKey, config.Now().UTC())
	var resolveErr error
	switch {
	case err != nil:
		resolveErr = err
		_ = config.Store.RecordAttempt(ctx, CodeResolveFailed)
	case response.NotModified:
		if err := config.Store.RecordAttempt(ctx, ""); err != nil {
			return err
		}
	default:
		if err := syncer.apply(ctx, *response.Delivery, head, keysetFailed); err != nil {
			return err
		}
	}
	// Downloads and materialization also run when the license service is
	// unreachable for the catalog (a lease change can make a stored entry
	// usable or unusable without a new delivery).
	changed, downloadErr := syncer.download(ctx)
	materialized, err := config.Store.Materialize(ctx)
	if err != nil {
		return err
	}
	// Content keys of mounted sealed packs, wrapped again for every active
	// node key (rule.pack.key_wrap); site publication and node key changes
	// are picked up here too.
	if len(config.EncryptionKey) > 0 {
		wrapped, err := config.Store.WrapNodeKeys(ctx, config.EncryptionKey)
		if err != nil {
			return err
		}
		materialized += wrapped
	}
	if (changed || materialized > 0) && config.OnChanged != nil {
		config.OnChanged(ctx)
	}
	if resolveErr != nil {
		return resolveErr
	}
	return downloadErr
}

func (syncer *Syncer) apply(ctx context.Context, delivery artifactcatalog.Signed, head *artifactcatalog.Head, keysetFailed bool) error {
	config := syncer.config
	verified, err := artifactcatalog.Verify(delivery, config.Trust, artifactcatalog.VerifyOptions{
		Now: config.Now().UTC(), InstallationID: config.InstallationID.String(), Head: head})
	switch {
	case errors.Is(err, artifactcatalog.ErrNotYetValid):
		return config.Store.RecordAttempt(ctx, CodeNotYetValid)
	case err != nil && errors.Is(err, entitlement.ErrUnknownKey) && keysetFailed:
		// The keyset could not be refreshed: retry, the key may be new.
		_ = config.Store.RecordAttempt(ctx, CodeUnknownKey)
		return err
	case err != nil:
		code := RejectionCode(err)
		config.Logger.Warn("artifact catalog delivery rejected; keeping the last verified catalog", "code", code,
			"delivery_id", delivery.Envelope.DeliveryID, "scope_revision", delivery.Envelope.ScopeRevision)
		return config.Store.RejectDelivery(ctx, delivery.Envelope, code)
	case verified.Duplicate:
		return config.Store.RecordAttempt(ctx, "")
	}
	if err := config.Store.ApplyCatalog(ctx, verified, head); err != nil {
		if !errors.Is(err, ErrStaleApply) {
			_ = config.Store.RecordAttempt(ctx, CodeApplyFailed)
		}
		return err
	}
	config.Logger.Info("artifact catalog applied", "scope_revision", verified.Signed.Envelope.ScopeRevision,
		"entries", len(verified.Signed.Catalog.Entries))
	return nil
}

// download fetches every pending entry; bytes that do not match the signed
// entry are rejected and the previous download kept. It returns whether a
// download was stored and the first transport failure.
func (syncer *Syncer) download(ctx context.Context) (bool, error) {
	config := syncer.config
	pending, err := config.Store.PendingDownloads(ctx)
	if err != nil {
		return false, err
	}
	changed := false
	var firstErr error
	for _, entry := range pending {
		content, err := config.Client.Fetch(ctx, config.InstallationID, entry, config.PrivateKey, config.Now().UTC())
		if err != nil {
			if ctx.Err() != nil {
				return changed, ctx.Err()
			}
			_ = config.Store.RejectDownload(ctx, entry, CodeDownloadFailed, false)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if entry.Kind == artifactcatalog.KindRulePack {
			if _, err := verifyRulePack(entry, content, config.EncryptionKey); err != nil {
				if errors.Is(err, artifactcatalog.ErrContentMismatch) {
					if err := config.Store.RejectDownload(ctx, entry, CodeContentMismatch, true); err != nil {
						return changed, err
					}
					continue
				}
				config.Logger.Warn("rule pack rejected; keeping the previous download", "artifact_id", entry.ArtifactID,
					"revision", entry.Revision, "error", err)
				if err := config.Store.RejectDecrypt(ctx, entry, err); err != nil {
					return changed, err
				}
				continue
			}
		} else if err := VerifyArtifact(entry, content); err != nil {
			config.Logger.Warn("artifact bytes rejected; keeping the previous download", "artifact_id", entry.ArtifactID,
				"revision", entry.Revision, "error", err)
			if err := config.Store.RejectDownload(ctx, entry, CodeContentMismatch, true); err != nil {
				return changed, err
			}
			continue
		}
		stored, err := config.Store.StoreDownload(ctx, entry, content)
		if err != nil {
			return changed, err
		}
		if stored {
			changed = true
			config.Logger.Info("artifact downloaded", "artifact_id", entry.ArtifactID, "revision", entry.Revision)
		}
	}
	return changed, firstErr
}

// VerifyArtifact checks bytes against their signed entry and, per kind,
// that they decode to what the entry says (the system rule it names, an IP
// library of that build).
func VerifyArtifact(entry artifactcatalog.Entry, content []byte) error {
	if artifactcatalog.IsCRSAppPackEntry(entry) {
		// An application exclusion pack: canonical bytes of a system/app-* pack.
		compiled, _, err := rulepack.LoadCRSApp(content, entry.SHA256)
		if packID, _ := artifactcatalog.CRSProfilePackID(entry); err != nil || compiled.Pack.Version != entry.Version ||
			compiled.Pack.PackID != packID {
			return fmt.Errorf("%w: application exclusion pack %s", artifactcatalog.ErrContentMismatch, entry.ArtifactID)
		}
		return nil
	}
	if _, pack := artifactcatalog.CRSProfilePackID(entry); pack {
		// A CRS profile pack: canonical rule pack bytes of a system/crs-* pack.
		compiled, _, err := rulepack.LoadCRSProfile(content, entry.SHA256)
		if err != nil || compiled.Pack.Version != entry.Version {
			return fmt.Errorf("%w: CRS profile pack %s", artifactcatalog.ErrContentMismatch, entry.ArtifactID)
		}
		if packID, _ := artifactcatalog.CRSProfilePackID(entry); compiled.Pack.PackID != packID {
			return fmt.Errorf("%w: CRS profile pack %s", artifactcatalog.ErrContentMismatch, entry.ArtifactID)
		}
		return nil
	}
	switch entry.Kind {
	case artifactcatalog.KindRuleset, artifactcatalog.KindCRSProfile:
		_, err := artifactcatalog.DecodeRulesetItem(entry, content)
		return err
	case artifactcatalog.KindIPIntel:
		_, err := artifactcatalog.VerifyIPIntel(entry, content)
		return err
	case artifactcatalog.KindMarketRulePack, artifactcatalog.KindMarketTheme:
		_, err := verifyDataPack(entry, content)
		return err
	case artifactcatalog.KindPluginUI:
		_, err := verifyPluginUI(entry, content)
		return err
	case artifactcatalog.KindPluginProvider:
		_, err := verifyPluginProvider(entry, content)
		return err
	case artifactcatalog.KindDataset:
		if entry.ArtifactID != artifactcatalog.TrustedCrawlersID {
			return ErrUnsupported
		}
		_, err := crawlerdefaults.DecodeDataset(content)
		return err
	case artifactcatalog.KindEngineModule:
		// Structure only: the platform release signature is the node's to judge.
		_, err := artifactcatalog.VerifyEngineModule(entry, content)
		return err
	default:
		return ErrUnsupported
	}
}

func (syncer *Syncer) registerEncryptionKey(ctx context.Context) error {
	config := syncer.config
	registrar, ok := config.Client.(EncryptionKeyRegistrar)
	if syncer.registered || len(config.EncryptionKey) == 0 || !ok {
		return nil
	}
	public, err := rulepack.X25519PublicKey(config.EncryptionKey)
	if err != nil {
		return err
	}
	response, err := registrar.RegisterEncryptionKey(ctx, config.InstallationID, public, config.PrivateKey, config.Now().UTC())
	if err != nil {
		return EncryptionKeyRegistrationError(rulepack.X25519KeyID(public), err)
	}
	if response.KeyID != rulepack.X25519KeyID(public) {
		return ErrInvalidResponse
	}
	syncer.registered = true
	if response.Changed {
		config.Logger.Info("installation encryption key registered", "key_id", response.KeyID)
	}
	return nil
}

// ErrEncryptionKeyTaken: the license service already holds this encryption
// public key for another installation (its unique constraint).
var ErrEncryptionKeyTaken = errors.New("installation encryption key is already registered to another installation")

// EncryptionKeyRegistrationError explains a failed registration: a conflict
// means the key file was copied from another installation and must be
// replaced by a new key (generate-installation-encryption-key), never shared.
func EncryptionKeyRegistrationError(keyID string, err error) error {
	var service *ServiceError
	if errors.As(err, &service) && service.StatusCode == http.StatusConflict {
		return fmt.Errorf("%w (key_id %s): this key file was copied from another installation; generate a new one with "+
			"control-api generate-installation-encryption-key and register it again: %w", ErrEncryptionKeyTaken, keyID, err)
	}
	return fmt.Errorf("register installation encryption key %s: %w", keyID, err)
}
