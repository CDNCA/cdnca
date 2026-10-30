package dnsproviderremote

import "testing"

func TestHuaweiDirectNotFoundCannotOverrideListedRecord(t *testing.T) {
	for _, operation := range []string{"observe", "delete"} {
		t.Run(operation, func(t *testing.T) {
			fixture := &huaweiListAbsenceFixture{listExists: []bool{true}}
			adapter, source, challenge := newHuaweiListAbsenceAdapter(t, fixture)
			var err error
			if operation == "observe" {
				err = adapter.ObserveTXT(t.Context(), challenge)
			} else {
				err = adapter.DeleteTXT(t.Context(), challenge)
			}
			assertHuaweiAbsenceError(t, err, CodeUnavailable, true)
			if fixture.listCalls != 1 || fixture.directCalls != 1 || len(fixture.deletedIDs) != 0 {
				t.Fatalf("list=%d direct=%d DELETE=%v, want 1/1/[]",
					fixture.listCalls, fixture.directCalls, fixture.deletedIDs)
			}
			if !source.credentialsCleared() {
				t.Fatal("operation retained decrypted credentials")
			}
		})
	}
}
