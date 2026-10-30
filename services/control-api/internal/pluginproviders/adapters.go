package pluginproviders

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/icpquery"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
)

// Clients is the usable-provider client source (Service).
type Clients interface {
	Client(ctx context.Context, pluginID, kind string) (*pluginprovider.Client, error)
}

// SMSTransport is the notificationruntime transport of a third-party SMS
// plugin (the same interface as the official aliyun / submail channels).
// The plugin is resolved on every send: disabling it stops sending at once.
type SMSTransport struct {
	Clients  Clients
	PluginID string
}

var _ notificationruntime.ProviderTransport = SMSTransport{}

func (transport SMSTransport) Ready(ctx context.Context) error {
	if transport.Clients == nil {
		return ErrNotUsable
	}
	_, err := transport.Clients.Client(ctx, transport.PluginID, pluginprovider.KindSMS)
	return err
}

func (transport SMSTransport) Send(ctx context.Context, message notificationruntime.ProviderMessage) (
	notificationruntime.ProviderResult, error) {
	client, err := transport.Clients.Client(ctx, transport.PluginID, pluginprovider.KindSMS)
	if err != nil {
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderTemporaryFailure,
			Code: "plugin_provider_not_usable"}, nil
	}
	var response pluginprovider.SMSSendResponse
	err = client.Call(ctx, pluginprovider.KindSMS, "send", pluginprovider.SMSSendRequest{
		RequestHeader: pluginprovider.RequestHeader{Protocol: pluginprovider.Protocol}, To: message.Contact,
		TemplateID: message.TemplateID, Params: message.Params, Body: message.Body,
		IdempotencyKey: message.IdempotencyKey}, &response)
	if err == nil {
		if response.DeliveryID == "" || len(response.DeliveryID) > 256 {
			return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderUnknown,
				Code: pluginprovider.CodeInvalidResponse}, nil
		}
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted,
			ProviderDeliveryID: response.DeliveryID}, nil
	}
	return pluginCallFailure(err), nil
}

func (SMSTransport) Close(context.Context) error { return nil }

// MailTransport is the notificationruntime email transport of a third-party
// mail plugin chosen as the system mail sender (systemmailsettings
// mail_provider plugin:<id>). Like SMSTransport the plugin is resolved on
// every send; an unusable plugin fails the send temporarily and no other
// sender takes over.
type MailTransport struct {
	Clients  Clients
	PluginID string
	// HTML renders the optional HTML alternative (the theme email layout).
	HTML func(ctx context.Context, message notificationruntime.ProviderMessage) string
}

var _ notificationruntime.ProviderTransport = MailTransport{}

// Ready only checks the plugin is usable (contract passed, enabled), as
// SMSTransport does: a remote outage must not stop the process from
// starting. The plugin's health action is exercised by the contract runner.
func (transport MailTransport) Ready(ctx context.Context) error {
	if transport.Clients == nil {
		return ErrNotUsable
	}
	_, err := transport.Clients.Client(ctx, transport.PluginID, pluginprovider.KindMail)
	return err
}

func (transport MailTransport) Send(ctx context.Context, message notificationruntime.ProviderMessage) (
	notificationruntime.ProviderResult, error) {
	if transport.Clients == nil {
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderTemporaryFailure,
			Code: "plugin_provider_not_usable"}, nil
	}
	client, err := transport.Clients.Client(ctx, transport.PluginID, pluginprovider.KindMail)
	if err != nil {
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderTemporaryFailure,
			Code: "plugin_provider_not_usable"}, nil
	}
	text := message.Body
	if message.ActionURL != "" {
		text += "\n\n" + message.ActionURL
	}
	request := pluginprovider.MailSendRequest{RequestHeader: pluginprovider.RequestHeader{Protocol: pluginprovider.Protocol},
		To: message.Contact, Subject: message.Subject, Text: text, IdempotencyKey: message.IdempotencyKey}
	if transport.HTML != nil {
		request.HTML = transport.HTML(ctx, message)
	}
	var response pluginprovider.MailSendResponse
	err = client.Call(ctx, pluginprovider.KindMail, "send", request, &response)
	if err == nil {
		if response.MessageID == "" || len(response.MessageID) > 256 {
			return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderUnknown,
				Code: pluginprovider.CodeInvalidResponse}, nil
		}
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted,
			ProviderDeliveryID: response.MessageID}, nil
	}
	return pluginCallFailure(err), nil
}

func (MailTransport) Close(context.Context) error { return nil }

// pluginCallFailure maps a plugin call error to a send result (shared by the
// SMS and mail transports).
func pluginCallFailure(err error) notificationruntime.ProviderResult {
	var callErr *pluginprovider.Error
	if !errors.As(err, &callErr) {
		return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderUnknown, Code: "provider_error"}
	}
	result := notificationruntime.ProviderResult{Code: "plugin_" + callErr.Code}
	switch {
	case callErr.Code == pluginprovider.CodeRateLimited || callErr.Code == "quota_exceeded":
		result.Disposition, result.RetryAfter = notificationruntime.ProviderRateLimited, time.Minute
	case callErr.Code == pluginprovider.CodeTimeout || callErr.Code == pluginprovider.CodeInvalidResponse ||
		callErr.Code == pluginprovider.CodeBadResponseSignature:
		// The plugin may have sent it: the idempotency key protects a retry.
		result.Disposition = notificationruntime.ProviderUnknown
	case callErr.Temporary:
		result.Disposition = notificationruntime.ProviderTemporaryFailure
	default:
		result.Disposition = notificationruntime.ProviderPermanentFailure
	}
	return result
}

// QueryICP asks a third-party ICP plugin whether hostname's registrable
// domain is filed, as icpquery.Client.Query does for the official sources.
func QueryICP(ctx context.Context, clients Clients, pluginID, hostname string, now time.Time) (icpquery.Result, error) {
	domain, err := icpquery.RegistrableDomain(hostname)
	if err != nil {
		return icpquery.Result{}, icpquery.ErrInvalidInput
	}
	client, err := clients.Client(ctx, pluginID, pluginprovider.KindICP)
	if err != nil {
		return icpquery.Result{}, icpquery.ErrTransport
	}
	var response pluginprovider.ICPQueryResponse
	err = client.Call(ctx, pluginprovider.KindICP, "query", pluginprovider.ICPQueryRequest{
		RequestHeader: pluginprovider.RequestHeader{Protocol: pluginprovider.Protocol}, Domain: domain}, &response)
	switch code := pluginprovider.CodeOf(err); {
	case err == nil:
	case code == pluginprovider.CodeUnauthorized:
		return icpquery.Result{}, icpquery.ErrCredential
	case code == "quota_exceeded":
		return icpquery.Result{}, icpquery.ErrQuota
	case code == pluginprovider.CodeRateLimited:
		return icpquery.Result{}, icpquery.ErrRateLimited
	case code == pluginprovider.CodeUnavailable || code == pluginprovider.CodeTimeout || code == pluginprovider.CodeBlockedAddress:
		return icpquery.Result{}, icpquery.ErrTransport
	default:
		return icpquery.Result{}, icpquery.ErrProvider
	}
	result := icpquery.Result{Domain: domain, Provider: icpquery.Provider("plugin:" + pluginID), CheckedAt: now.UTC()}
	switch response.Status {
	case pluginprovider.ICPFiled:
		result.Status = icpquery.Filed
		result.Licence, result.Subject = clip(response.Licence), clip(response.Subject)
	case pluginprovider.ICPUnfiled:
		result.Status = icpquery.Unfiled
	default:
		return icpquery.Result{}, icpquery.ErrProvider
	}
	return result, nil
}

func clip(value string) string {
	value = strings.TrimSpace(value)
	if len([]rune(value)) > 128 {
		return string([]rune(value)[:128])
	}
	return value
}
