package errorpagecontrol

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRuntimeActorFormattingRedactsSession(t *testing.T) {
	const credential = "cdnca-sensitive-error-page-session"
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: uuid.New()}, rawSession: credential}
	encoded, err := json.Marshal(actor)
	if err != nil {
		t.Fatal(err)
	}
	encodedPointer, err := json.Marshal(&actor)
	if err != nil {
		t.Fatal(err)
	}
	encodedNested, err := json.Marshal(map[string]any{"actor": actor})
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		fmt.Sprintf("%v", actor), fmt.Sprintf("%+v", actor), fmt.Sprintf("%#v", actor),
		fmt.Sprintf("%s", actor), fmt.Sprintf("%q", actor), fmt.Sprintf("%x", actor),
		fmt.Sprintf("%X", actor), fmt.Sprintf("%v", &actor), fmt.Sprintf("%#v", &actor),
		actor.String(), actor.GoString(), string(encoded), string(encodedPointer), string(encodedNested),
	} {
		if strings.Contains(output, credential) {
			t.Fatalf("session leaked through %q", output)
		}
	}
}
