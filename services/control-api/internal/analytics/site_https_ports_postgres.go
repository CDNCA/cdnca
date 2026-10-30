package analytics

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresSiteHTTPSPortReader reads sites.https_ports for the URL ranking's
// scheme. The site IDs come from an already scoped ranking page, and only
// ports are returned.
type PostgresSiteHTTPSPortReader struct {
	pool *pgxpool.Pool
}

func NewPostgresSiteHTTPSPortReader(pool *pgxpool.Pool) *PostgresSiteHTTPSPortReader {
	return &PostgresSiteHTTPSPortReader{pool: pool}
}

func (reader *PostgresSiteHTTPSPortReader) SiteHTTPSPorts(ctx context.Context, siteIDs []string) (map[string][]uint16, error) {
	rows, err := reader.pool.Query(ctx,
		`SELECT id::text, https_ports FROM sites WHERE id = ANY($1::uuid[])`, siteIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]uint16, len(siteIDs))
	for rows.Next() {
		var id string
		var raw []string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		result[id] = parseHTTPSPorts(raw)
	}
	return result, rows.Err()
}

// parseHTTPSPorts keeps the valid ports of sites.https_ports (text[]).
func parseHTTPSPorts(raw []string) []uint16 {
	ports := make([]uint16, 0, len(raw))
	for _, value := range raw {
		if port, err := strconv.ParseUint(value, 10, 16); err == nil && port != 0 {
			ports = append(ports, uint16(port))
		}
	}
	return ports
}
