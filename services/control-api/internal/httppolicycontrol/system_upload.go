package httppolicycontrol

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/jackc/pgx/v5"
)

// SystemMaxUploadBytes is the upload limit a site without an HTTP policy has
// on the node: the active system client_max_body_size (nginx's 1m when none
// is published, edgeskeleton.DefaultSystemMaxBody), capped at what an HTTP
// policy accepts. A new policy starts from it, so adding only headers keeps
// the site's limit.
func SystemMaxUploadBytes(ctx context.Context, tx pgx.Tx) (int64, error) {
	active, found, err := systemconfig.LoadActiveEdgeNginx(ctx, tx)
	if err != nil {
		return 0, err
	}
	if !found || active.Nginx.ClientMaxBodyBytes < 1 {
		return 1 << 20, nil
	}
	return min(active.Nginx.ClientMaxBodyBytes, MaxUploadBytes), nil
}
