package acmeworker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/acme"
)

// FailureDetail describes why err failed for an operator log, without
// anything that may carry a secret: a database error gives its SQLSTATE,
// object names and message (never Detail, which can quote row values), an
// ACME problem its status, type and CA detail, any other cause only its Go
// type. Empty when err records no cause.
func FailureDetail(err error) string {
	var workerErr *Error
	if errors.As(err, &workerErr) {
		err = workerErr.cause
	}
	if err == nil {
		return ""
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		parts := []string{"sqlstate=" + pgErr.Code}
		for _, field := range [][2]string{
			{"table", pgErr.TableName}, {"column", pgErr.ColumnName}, {"constraint", pgErr.ConstraintName},
		} {
			if field[1] != "" {
				parts = append(parts, field[0]+"="+field[1])
			}
		}
		return strings.Join(append(parts, "message="+pgErr.Message), " ")
	}
	var problem *acme.Error
	if errors.As(err, &problem) {
		return fmt.Sprintf("acme_status=%d acme_problem=%s acme_detail=%q",
			problem.StatusCode, problem.ProblemType, problem.Detail)
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context deadline exceeded"
	}
	var inner *Error
	if errors.As(err, &inner) {
		return "code=" + string(inner.Code)
	}
	// A stable lower-case code (a sentinel such as acme_runtime_conflict) is
	// safe to print; any other message may quote a URL or a value.
	if message := err.Error(); stableCodePattern.MatchString(message) {
		return "cause=" + message
	}
	return fmt.Sprintf("cause_type=%T", err)
}

var stableCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
