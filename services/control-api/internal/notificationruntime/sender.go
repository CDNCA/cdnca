package notificationruntime

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

type memberSender struct {
	resolver  MemberContactResolver
	providers map[notification.Channel]ProviderTransport
	timeout   time.Duration
	now       func() time.Time
}

type recoverySender struct {
	providers map[notification.Channel]ProviderTransport
	timeout   time.Duration
	now       func() time.Time
}

func newMemberSender(
	resolver MemberContactResolver,
	providers map[notification.Channel]ProviderTransport,
	timeout time.Duration,
) *memberSender {
	return &memberSender{resolver: resolver, providers: copyProviders(providers), timeout: timeout}
}

func newRecoverySender(providers map[notification.Channel]ProviderTransport, timeout time.Duration) *recoverySender {
	return &recoverySender{providers: copyProviders(providers), timeout: timeout}
}

func (s *memberSender) Send(ctx context.Context, attempt notification.DeliveryAttempt) notification.SendResult {
	if s == nil || s.resolver == nil || !validMemberAttempt(attempt) {
		return failed(notification.FailurePermanent, "sender_contract_invalid", 0)
	}
	provider := s.providers[attempt.Channel]
	if provider == nil {
		return failed(notification.FailureTemporary, "provider_unavailable", 0)
	}
	resolution := s.resolver.Resolve(ctx, attempt.ScopeID, attempt.RecipientID, attempt.Channel)
	if resolution.Failure != nil {
		if resolution.Contact != "" || !validFailure(*resolution.Failure) {
			return failed(notification.FailurePermanent, "resolver_contract_invalid", 0)
		}
		return notification.SendResult{Failure: resolution.Failure}
	}
	if resolution.Contact == "" {
		return failed(notification.FailurePermanent, "recipient_unavailable", 0)
	}
	return sendProvider(ctx, provider, s.timeout, ProviderMessage{
		OutboxID: attempt.OutboxID, Channel: attempt.Channel, Contact: resolution.Contact,
		Subject: attempt.Subject, Body: attempt.Body, IdempotencyKey: attempt.DedupKey,
		AttemptNumber: attempt.AttemptNumber, TemplateID: attempt.Template.ID, Params: attempt.Params,
		ScopeID: attempt.ScopeID,
	}, s.now)
}

func (s *recoverySender) SendRecovery(
	ctx context.Context,
	delivery accountrecovery.RecoveryDelivery,
) notification.SendResult {
	if s == nil || delivery.OutboxID == uuid.Nil || !validChannel(delivery.Channel) ||
		delivery.Contact == "" || delivery.IdempotencyKey == "" || delivery.AttemptNumber < 1 {
		return failed(notification.FailurePermanent, "sender_contract_invalid", 0)
	}
	provider := s.providers[delivery.Channel]
	if provider == nil {
		return failed(notification.FailureTemporary, "provider_unavailable", 0)
	}
	return sendProvider(ctx, provider, s.timeout, ProviderMessage{
		OutboxID: delivery.OutboxID, Channel: delivery.Channel, Contact: delivery.Contact,
		Subject: delivery.Subject, Body: delivery.Body, ActionURL: delivery.RecoveryURL,
		IdempotencyKey: delivery.IdempotencyKey, AttemptNumber: delivery.AttemptNumber,
		TemplateID: delivery.TemplateID, Params: delivery.Params,
	}, s.now)
}

func sendProvider(
	ctx context.Context,
	provider ProviderTransport,
	timeout time.Duration,
	message ProviderMessage,
	now func() time.Time,
) (deliveryResult notification.SendResult) {
	if ctx == nil {
		return failed(notification.FailureTemporary, "provider_cancelled", 0)
	}
	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err, panicked, observation := CallObservedProvider(sendCtx, provider, message, now)
	defer func() { deliveryResult.Observation = observation }()
	if panicked {
		return notification.SendResult{Disposition: notification.SendUnknown, Provider: providerName(message.Channel)}
	}
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(sendCtx.Err(), context.DeadlineExceeded):
			return notification.SendResult{Disposition: notification.SendUnknown, Provider: providerName(message.Channel)}
		case errors.Is(err, context.Canceled) || errors.Is(sendCtx.Err(), context.Canceled):
			return notification.SendResult{Disposition: notification.SendUnknown, Provider: providerName(message.Channel)}
		default:
			return notification.SendResult{Disposition: notification.SendUnknown, Provider: providerName(message.Channel)}
		}
	}
	if !validProviderResult(result) {
		return failed(notification.FailurePermanent, "provider_contract_invalid", 0)
	}
	switch result.Disposition {
	case ProviderAccepted:
		return notification.SendResult{
			Disposition: notification.SendAccepted, Provider: providerName(message.Channel),
			ProviderDeliveryID: result.ProviderDeliveryID,
		}
	case ProviderUnknown:
		return notification.SendResult{Disposition: notification.SendUnknown, Provider: providerName(message.Channel)}
	case ProviderTemporaryFailure, ProviderRateLimited:
		return failed(notification.FailureTemporary, result.Code, result.RetryAfter)
	case ProviderPermanentFailure:
		return failed(notification.FailurePermanent, result.Code, 0)
	default:
		return failed(notification.FailurePermanent, "provider_contract_invalid", 0)
	}
}

// CallObservedProvider records only actual transport invocations. The returned
// timestamp is neither provider acceptance nor confirmed recipient delivery.
func CallObservedProvider(ctx context.Context, provider ProviderTransport, message ProviderMessage, now func() time.Time) (ProviderResult, error, bool, *notification.DispatchObservation) {
	if ctx == nil || provider == nil {
		return ProviderResult{}, ErrProviderUnavailable, false, nil
	}
	if err := ctx.Err(); err != nil {
		return ProviderResult{}, err, false, nil
	}
	if now == nil {
		now = time.Now
	}
	observation := notification.NewDispatchObservation(message.Channel, message.Contact, now())
	result, err, panicked := callProvider(ctx, provider, message)
	return result, err, panicked, observation
}

func callProvider(
	ctx context.Context,
	provider ProviderTransport,
	message ProviderMessage,
) (result ProviderResult, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			result = ProviderResult{}
			err = nil
			panicked = true
		}
	}()
	result, err = provider.Send(ctx, message)
	return result, err, false
}

func validMemberAttempt(attempt notification.DeliveryAttempt) bool {
	return attempt.OutboxID != uuid.Nil && attempt.ScopeID != uuid.Nil && attempt.RecipientID != uuid.Nil &&
		validChannel(attempt.Channel) && attempt.DedupKey != "" && attempt.AttemptNumber > 0
}

func validProviderResult(result ProviderResult) bool {
	switch result.Disposition {
	case ProviderAccepted:
		return result.Code == "" && result.RetryAfter == 0 && validProviderDeliveryID(result.ProviderDeliveryID)
	case ProviderUnknown:
		return result.Code == "" && result.RetryAfter == 0 && result.ProviderDeliveryID == ""
	case ProviderTemporaryFailure:
		return validCode(result.Code) && result.RetryAfter >= 0
	case ProviderPermanentFailure:
		return validCode(result.Code) && result.RetryAfter == 0
	case ProviderRateLimited:
		return validCode(result.Code) && result.RetryAfter > 0
	default:
		return false
	}
}

func providerName(channel notification.Channel) string {
	return "configured_" + string(channel)
}

func validProviderDeliveryID(value string) bool {
	if len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == '\u007f' {
			return false
		}
	}
	return true
}

func validFailure(failure notification.Failure) bool {
	return (failure.Class == notification.FailureTemporary || failure.Class == notification.FailurePermanent) &&
		validCode(failure.Code) && failure.RetryAfter >= 0 &&
		(failure.Class == notification.FailureTemporary || failure.RetryAfter == 0)
}

func validCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, character := range code {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	compact := strings.ReplaceAll(code, "_", "")
	for _, marker := range []string{
		"secret", "password", "passwd", "token", "credential", "authorization", "cookie", "privatekey", "apikey", "otp",
	} {
		if strings.Contains(compact, marker) {
			return false
		}
	}
	return true
}

func validChannel(channel notification.Channel) bool {
	return channel == notification.ChannelEmail || channel == notification.ChannelSMS
}

func failed(class notification.FailureClass, code string, retryAfter time.Duration) notification.SendResult {
	failure := notification.Failure{Class: class, Code: code, RetryAfter: retryAfter}
	return notification.SendResult{Failure: &failure}
}

func copyProviders(source map[notification.Channel]ProviderTransport) map[notification.Channel]ProviderTransport {
	cloned := make(map[notification.Channel]ProviderTransport, len(source))
	for channel, provider := range source {
		cloned[channel] = provider
	}
	return cloned
}
