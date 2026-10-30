package nodednspupprobe

import (
	"sort"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
)

// SelectCheckpoints picks up to PointsPerGroup online checkpoints of every
// selected group, rotating with round so the probing points change between
// rounds. domestic takes mainland checkpoints of any carrier. An empty
// selection (no matching checkpoint) means no dnspup round.
func SelectCheckpoints(checkpoints []dnspupprobe.Checkpoint, settings Settings, round int64) []string {
	byGroup := map[string][]string{}
	for _, checkpoint := range checkpoints {
		if checkpoint.Status != "" && checkpoint.Status != "online" {
			continue
		}
		region, _ := marketprobe.Region(checkpoint.Region)
		carrier, _ := marketprobe.Carrier(checkpoint.ISP)
		group := CheckpointGroup(dnspupprobe.Vote{Region: region, Carrier: carrier})
		if group == "" || checkpoint.ID == "" {
			continue
		}
		byGroup[group] = append(byGroup[group], checkpoint.ID)
		if group != GroupOverseas && group != GroupDomestic {
			byGroup[GroupDomestic] = append(byGroup[GroupDomestic], checkpoint.ID)
		}
	}
	seen := map[string]bool{}
	var selected []string
	for _, group := range settings.Groups {
		ids := byGroup[group]
		sort.Strings(ids)
		if len(ids) == 0 {
			continue
		}
		offset := int(round % int64(len(ids)))
		taken := 0
		for index := 0; index < len(ids) && taken < settings.PointsPerGroup; index++ {
			id := ids[(offset+index)%len(ids)]
			if seen[id] {
				continue
			}
			seen[id] = true
			selected = append(selected, id)
			taken++
		}
	}
	return selected
}
