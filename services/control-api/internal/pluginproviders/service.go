package pluginproviders

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/google/uuid"
)

// Service runs installation contracts and builds provider clients.
type Service struct {
	Store *Store
	// Signer is the control plane installation identity; nil = provider
	// plugins are unavailable (contracts cannot run, nothing is enabled).
	Signer *pluginprovider.Signer
	// HTTPClient replaces the public-address-only production client (tests).
	HTTPClient *http.Client
	Now        func() time.Time
	Logger     *slog.Logger
	// StepUp consumes the MFA proof of a payment plugin enable; nil = no
	// payment plugin can be enabled.
	StepUp StepUpVerifier
}

func (service *Service) options() pluginprovider.Options {
	return pluginprovider.Options{HTTPClient: service.HTTPClient, Now: service.Now}
}

// Client returns a client for a usable provider of kind.
func (service *Service) Client(ctx context.Context, pluginID, kind string) (*pluginprovider.Client, error) {
	if service == nil || service.Store == nil || service.Signer == nil {
		return nil, ErrNotUsable
	}
	declaration, err := service.Store.Usable(ctx, pluginID, kind)
	if err != nil {
		return nil, err
	}
	return pluginprovider.NewClient(declaration, *service.Signer, service.options())
}

// RunContract runs the installation contract of one provider and records
// the report (actor uuid.Nil = the background runner).
func (service *Service) RunContract(ctx context.Context, actor Actor, pluginID string) (Provider, error) {
	if service == nil || service.Store == nil || service.Signer == nil {
		return Provider{}, ErrNotUsable
	}
	provider, err := service.Store.Get(ctx, pluginID)
	if err != nil {
		return Provider{}, err
	}
	if provider.Status != "active" {
		return Provider{}, ErrNotUsable
	}
	client, err := pluginprovider.NewClient(provider.declaration, *service.Signer, service.options())
	if err != nil {
		return Provider{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	report := pluginprovider.RunContract(runCtx, client)
	return service.Store.RecordContract(ctx, actor, provider, report)
}

// RunPending runs the contract of every provider still pending (new or
// upgraded declarations); the artifact sync wakes it after materializing.
func (service *Service) RunPending(ctx context.Context) int {
	if service == nil || service.Store == nil || service.Signer == nil {
		return 0
	}
	pending, err := service.Store.Pending(ctx)
	if err != nil {
		service.log().Warn("provider plugin contract: list pending", "error", err)
		return 0
	}
	ran := 0
	for _, provider := range pending {
		if _, err := service.RunContract(ctx, Actor{}, provider.PluginID); err != nil && !errors.Is(err, ErrConflict) {
			service.log().Warn("provider plugin contract", "plugin_id", provider.PluginID, "error", err)
			continue
		}
		ran++
	}
	return ran
}

func (service *Service) log() *slog.Logger {
	if service.Logger != nil {
		return service.Logger
	}
	return slog.Default()
}

// NewSigner builds the installation signer.
func NewSigner(installationID uuid.UUID, key ed25519.PrivateKey) (*pluginprovider.Signer, error) {
	if installationID == uuid.Nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	return &pluginprovider.Signer{InstallationID: installationID.String(), PrivateKey: key}, nil
}

// Step-up of a payment plugin enable (PA-23 high-risk permission): the
// administrator proves MFA for audience/action PaymentStepUpAction bound to
// the installation's tenant; the proof is consumed bound to
// PaymentBindingDigest(plugin, declaration) so it cannot enable anything
// else.
const PaymentStepUpAction = "plugin.provider.enable_payment"

// StepUpCheck is one proof to consume.
type StepUpCheck struct {
	UserID, ScopeID, SessionID uuid.UUID
	TenantID                   uuid.UUID
	Token                      string
	RequestID                  string
	Binding                    [32]byte
}

// StepUpVerifier consumes a step-up proof and returns its id (production:
// the MFA service, cmd/control-api).
type StepUpVerifier interface {
	Consume(ctx context.Context, check StepUpCheck) (uuid.UUID, error)
}

// ErrStepUpRequired: the proof is missing, invalid, consumed or bound to
// something else.
var ErrStepUpRequired = errors.New("payment provider plugin enable needs an MFA step-up")

// ErrRiskNotAcknowledged: the risk notice was not acknowledged.
var ErrRiskNotAcknowledged = errors.New("payment provider plugin risk notice not acknowledged")

// PaymentBindingDigest binds a proof to one plugin declaration.
func PaymentBindingDigest(pluginID, declarationSHA256 string) [32]byte {
	return sha256.Sum256([]byte("cdnca-plugin-provider-enable-payment/v1\n" + pluginID + "\n" + declarationSHA256))
}

// PaymentEnable is the high-risk confirmation of an enable request.
type PaymentEnable struct {
	SessionID        uuid.UUID
	StepUpToken      string
	RiskAcknowledged bool
}

// Enable turns a provider on. A payment provider needs confirm (MFA step-up
// and the acknowledged risk notice); every refusal is audited.
func (service *Service) Enable(ctx context.Context, actor Actor, pluginID string, confirm PaymentEnable) (Provider, error) {
	if service == nil || service.Store == nil {
		return Provider{}, ErrNotUsable
	}
	provider, err := service.Store.Get(ctx, pluginID)
	if err != nil {
		return Provider{}, err
	}
	if !provider.HighRisk || provider.Enabled {
		return service.Store.SetEnabled(ctx, actor, pluginID, true)
	}
	// The contract gate comes first: no proof is spent on a provider that
	// cannot be enabled anyway.
	if !(provider.Status == "active" && provider.ContractStatus == ContractPassed &&
		provider.contractSHA256 == provider.declarationSHA256) {
		return service.Store.SetEnabled(ctx, actor, pluginID, true)
	}
	reason := ""
	switch {
	case !confirm.RiskAcknowledged:
		reason, err = "risk_not_acknowledged", ErrRiskNotAcknowledged
	case service.StepUp == nil || confirm.StepUpToken == "" || confirm.SessionID == uuid.Nil || provider.TenantID == nil:
		reason, err = "step_up_required", ErrStepUpRequired
	}
	var proofID uuid.UUID
	if err == nil {
		proofID, err = service.StepUp.Consume(ctx, StepUpCheck{UserID: actor.UserID, ScopeID: actor.ScopeID,
			SessionID: confirm.SessionID, TenantID: *provider.TenantID, Token: confirm.StepUpToken, RequestID: actor.RequestID,
			Binding: PaymentBindingDigest(pluginID, provider.declarationSHA256)})
		if err != nil || proofID == uuid.Nil {
			reason, err = "step_up_required", ErrStepUpRequired
		}
	}
	if err != nil {
		if auditErr := service.Store.refuseEnable(ctx, actor, provider, reason); auditErr != nil {
			return Provider{}, auditErr
		}
		return Provider{}, err
	}
	return service.Store.setEnabled(ctx, actor, pluginID, true, &paymentConfirmation{proofID: proofID,
		declarationSHA256: provider.declarationSHA256})
}
