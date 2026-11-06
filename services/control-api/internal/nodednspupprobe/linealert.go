package nodednspupprobe

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	EventTypeLineUnreachable = notification.EventTypeNodeDNSPupLineUnreachable
	EventTypeLineRecovered   = notification.EventTypeNodeDNSPupLineRecovered
)

// LineCell is one node's carrier × area cell in a round. Area is the
// mainland province, else the region code (hk, us, …).
type LineCell struct {
	Carrier, Area string
	Failed, Total int
	Failures      map[string]int
	FailedIDs     []string
}

// TopFailure is the cell's most frequent failure category.
func (cell LineCell) TopFailure() string {
	top, count := "", 0
	for failure, seen := range cell.Failures {
		if seen > count || seen == count && failure < top {
			top, count = failure, seen
		}
	}
	return top
}

// Failing: at least LineAlertMinPoints failed checkpoints and more than
// FailurePercent of the cell.
func (cell LineCell) Failing(settings Settings) bool {
	return cell.Failed >= max(settings.LineAlertMinPoints, 1) && cell.Failed*100 > settings.FailurePercent*cell.Total
}

// LineCells groups one node's checkpoints of a round (every probed address):
// a checkpoint failed when it failed on every address it probed (like the
// node verdict). Checkpoints without a known area are left out.
func LineCells(rounds []RoundResult) map[[2]string]*LineCell {
	type seen struct {
		point Checkpoint
		ok    bool
	}
	byID := map[string]*seen{}
	var order []string
	for _, round := range rounds {
		for _, point := range round.Checkpoints {
			entry := byID[point.ID]
			if entry == nil {
				entry = &seen{point: point}
				byID[point.ID] = entry
				order = append(order, point.ID)
			}
			entry.ok = entry.ok || point.OK
			if !point.OK && point.Failure != "" {
				entry.point.Failure = point.Failure
			}
		}
	}
	cells := map[[2]string]*LineCell{}
	for _, id := range order {
		entry := byID[id]
		area := entry.point.Region
		if entry.point.Area == dnspupprobe.AreaMainland || area == "cn" {
			area = entry.point.Province
		}
		if area == "" {
			continue
		}
		carrier := entry.point.Line
		if carrier == "" {
			carrier = dnspupprobe.CarrierOther
		}
		key := [2]string{carrier, area}
		cell := cells[key]
		if cell == nil {
			cell = &LineCell{Carrier: carrier, Area: area, Failures: map[string]int{}}
			cells[key] = cell
		}
		cell.Total++
		if !entry.ok {
			cell.Failed++
			cell.FailedIDs = append(cell.FailedIDs, id)
			if entry.point.Failure != "" {
				cell.Failures[entry.point.Failure]++
			}
		}
	}
	return cells
}

var carrierTexts = map[string]string{
	dnspupprobe.CarrierTelecom: "电信", dnspupprobe.CarrierUnicom: "联通", dnspupprobe.CarrierMobile: "移动",
	dnspupprobe.CarrierEdu: "教育网", dnspupprobe.CarrierBGP: "BGP", dnspupprobe.CarrierOther: "其他运营商",
}

var regionTexts = map[string]string{"hk": "香港", "mo": "澳门", "tw": "台湾"}

// LineText is the alert's line name, e.g. "移动 · 广东".
func LineText(carrier, area string) string {
	place := area
	if text, ok := regionTexts[area]; ok {
		place = text
	} else if len(area) == 2 && area[0] < 0x80 {
		place = strings.ToUpper(area)
	}
	return carrierTexts[carrier] + " · " + place
}

// lineAlerts moves every observed cell's alert state, alerts transitions
// (platform nodes only) and, for a new failure with AutoDiagnose, runs one
// mtr from the cell's failed checkpoints after the commit.
func (runner *Runner) lineAlerts(ctx context.Context, targets []Target, rounds map[string]RoundResult, settings Settings,
	now time.Time) error {
	byNode := map[uuid.UUID][]RoundResult{}
	addresses := map[uuid.UUID]netipString{}
	scopes := map[uuid.UUID]uuid.UUID{}
	var order []uuid.UUID
	for _, target := range targets {
		round, ok := rounds[target.key()]
		if !ok {
			continue
		}
		if _, known := byNode[target.NodeID]; !known {
			order = append(order, target.NodeID)
			addresses[target.NodeID] = netipString(target.Address.String())
			scopes[target.NodeID] = target.ScopeID
		}
		byNode[target.NodeID] = append(byNode[target.NodeID], round)
	}
	var first error
	for _, nodeID := range order {
		cells := LineCells(byNode[nodeID])
		if len(cells) == 0 {
			continue
		}
		var diagnose []string
		err := pgx.BeginFunc(ctx, runner.pool, func(tx pgx.Tx) error {
			diagnose = nil
			keys := make([][2]string, 0, len(cells))
			for key := range cells {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
			for _, key := range keys {
				cell := cells[key]
				var consecutive int
				var failing bool
				var revision int64
				err := tx.QueryRow(ctx, `SELECT consecutive_failed,failing,alert_revision FROM node_dnspup_line_alert_states
					WHERE node_id=$1 AND carrier=$2 AND area=$3 FOR UPDATE`, nodeID, cell.Carrier, cell.Area).Scan(
					&consecutive, &failing, &revision)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				cellFailing := cell.Failing(settings)
				next := failing
				if cellFailing {
					consecutive++
					next = failing || consecutive >= max(settings.LineAlertRounds, 1)
				} else {
					consecutive, next = 0, false
				}
				changed := next != failing
				if changed {
					revision++
				}
				if _, err := tx.Exec(ctx, `INSERT INTO node_dnspup_line_alert_states(node_id,carrier,area,consecutive_failed,
					failing,failed_points,total_points,top_failure,alert_revision,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
					ON CONFLICT (node_id,carrier,area) DO UPDATE SET consecutive_failed=EXCLUDED.consecutive_failed,
					failing=EXCLUDED.failing,failed_points=EXCLUDED.failed_points,total_points=EXCLUDED.total_points,
					top_failure=EXCLUDED.top_failure,alert_revision=EXCLUDED.alert_revision,updated_at=EXCLUDED.updated_at`,
					nodeID, cell.Carrier, cell.Area, consecutive, next, cell.Failed, cell.Total, cell.TopFailure(), revision,
					now); err != nil {
					return err
				}
				if !changed {
					continue
				}
				if err := runner.alertLine(ctx, tx, nodeID, scopes[nodeID], *cell, next, revision, now); err != nil {
					return err
				}
				if next && settings.AutoDiagnose && diagnose == nil && len(cell.FailedIDs) > 0 {
					diagnose = cell.FailedIDs[:min(len(cell.FailedIDs), dnspupprobe.DiagnosePoints)]
				}
			}
			return nil
		})
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if diagnose != nil && runner.diagnose != nil {
			node := nodeID
			if _, err := runner.diagnose(ctx, "alert", dnspupprobe.DiagnoseInput{Target: string(addresses[nodeID]),
				NodeID: &node, Checkpoints: diagnose}); err != nil {
				runner.logger.Info("dnspup line alert diagnosis not started", "node", nodeID, "error", err)
			}
		}
	}
	return first
}

type netipString string

func (runner *Runner) alertLine(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID, cell LineCell, failing bool,
	revision int64, now time.Time) error {
	if runner.alerts == nil {
		return nil
	}
	var name, address string
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT node.name,COALESCE(host(node.ipv4),host(node.ipv6),'-'),
			scope.kind='platform' AND scope.tenant_id IS NULL
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id WHERE node.id=$1`, nodeID).Scan(&name,
		&address, &platform); err != nil {
		return err
	}
	if !platform {
		return nil
	}
	sms := notification.TemplateContext{"node_name": notification.PublicValue(name),
		"node_ip": notification.PublicValue(address), "line": notification.PublicValue(LineText(cell.Carrier, cell.Area))}
	eventType := EventTypeLineRecovered
	if failing {
		eventType = EventTypeLineUnreachable
		sms["failed"] = notification.PublicValue(strconv.Itoa(cell.Failed))
		sms["failure"] = notification.PublicValue(dnspupprobe.FailureTexts[cell.TopFailure()])
	}
	email := notification.TemplateContext{"occurred_at": notification.PublicValue(now.UTC().Format(time.RFC3339))}
	for key, value := range sms {
		email[key] = value
	}
	if failing {
		email["total"] = notification.PublicValue(strconv.Itoa(cell.Total))
		email["link"] = notification.PublicValue(dnspupprobe.SettingsPagePath + "?tab=matrix&node=" + nodeID.String())
	}
	return runner.enqueue(ctx, tx, scopeID, nodeAlertPermission, eventType,
		"node-dnspup-line/"+nodeID.String()+"/"+cell.Carrier+"/"+cell.Area+"/"+strconv.FormatInt(revision, 10), sms, email)
}
