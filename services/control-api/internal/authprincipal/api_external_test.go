package authprincipal_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/authprincipal"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ authprincipal.TransactionalAuthorizerV1 = externalFakeAuthorizer{}

type externalFakeAuthorizer struct{}

func (externalFakeAuthorizer) AuthorizeTx(
	context.Context,
	pgx.Tx,
	authprincipal.AuthenticatedPrincipalV1,
	uuid.UUID,
	string,
) (authprincipal.AuthorizedScopeV1, error) {
	return authprincipal.AuthorizedScopeV1{}, authprincipal.ErrPermissionDenied
}

func TestOpaqueValuesCannotBePopulatedExternally(t *testing.T) {
	values := map[string]any{
		"credential":       authprincipal.CredentialReferenceV1{},
		"principal":        authprincipal.AuthenticatedPrincipalV1{},
		"authorized scope": authprincipal.AuthorizedScopeV1{},
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			typeOfValue := reflect.TypeOf(value)
			for index := 0; index < typeOfValue.NumField(); index++ {
				if field := typeOfValue.Field(index); field.IsExported() {
					t.Fatalf("%s field %q is exported", name, field.Name)
				}
			}
			if value.(interface{ IsValid() bool }).IsValid() {
				t.Fatalf("zero %s is valid", name)
			}
		})
	}
}
