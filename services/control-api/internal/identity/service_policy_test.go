package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type publicSettingsReaderStub struct {
	settings systemusersettings.PublicSettings
	err      error
}

func (stub publicSettingsReaderStub) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return stub.settings, stub.err
}

func TestServiceSessionTTLUsesPublicPolicy(t *testing.T) {
	service := &Service{
		refreshTTL:     24 * time.Hour,
		publicSettings: publicSettingsReaderStub{settings: systemusersettings.PublicSettings{SessionTTLSeconds: 3600}},
	}
	got, err := service.sessionTTL(context.Background(), uuid.New())
	if err != nil || got != time.Hour {
		t.Fatalf("sessionTTL() = (%v, %v), want (1h, nil)", got, err)
	}
}

func TestServiceSessionTTLFallsBackWithoutPublicPolicy(t *testing.T) {
	service := &Service{refreshTTL: 24 * time.Hour}
	got, err := service.sessionTTL(context.Background(), uuid.New())
	if err != nil || got != 24*time.Hour {
		t.Fatalf("sessionTTL() = (%v, %v), want (24h, nil)", got, err)
	}
}

func TestServiceSessionTTLRejectsUnavailableOrInvalidPublicPolicy(t *testing.T) {
	tests := []struct {
		name     string
		reader   publicSettingsReaderStub
		wantText string
	}{
		{name: "unavailable", reader: publicSettingsReaderStub{err: errors.New("database unavailable")}, wantText: "load public session policy"},
		{name: "too short", reader: publicSettingsReaderStub{settings: systemusersettings.PublicSettings{SessionTTLSeconds: 299}}, wantText: "public session policy TTL is invalid"},
		{name: "too long", reader: publicSettingsReaderStub{settings: systemusersettings.PublicSettings{SessionTTLSeconds: 31536001}}, wantText: "public session policy TTL is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{refreshTTL: time.Hour, publicSettings: test.reader}
			if _, err := service.sessionTTL(context.Background(), uuid.New()); err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("sessionTTL() error = %v, want text %q", err, test.wantText)
			}
		})
	}
}
