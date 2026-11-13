package statuspage

import (
	"slices"
	"time"

	"github.com/google/uuid"
)

type builtPublic struct {
	components []PublicComponent
	// visible maps a component or group id to its public key; hidden ones are absent.
	visible map[uuid.UUID]string
	// statuses are the real (not unconfigured) statuses of the top-level entries.
	statuses []string
}

// span is when an incident was in effect; end is nil while it is still open.
func span(item Incident) (time.Time, *time.Time) {
	if item.Kind == KindMaintenance && item.ScheduledStart != nil {
		end := item.ScheduledEnd
		if item.ResolvedAt != nil {
			end = item.ResolvedAt
		}
		return *item.ScheduledStart, end
	}
	return item.StartedAt, item.ResolvedAt
}

// eventsFor returns the day-by-day view of the incidents touching any of refs.
func eventsFor(refs []uuid.UUID, incidents []Incident, now time.Time) func(time.Time) []PublicEvent {
	touching := []Incident{}
	seen := map[uuid.UUID]bool{}
	for _, item := range incidents {
		if seen[item.ID] {
			continue
		}
		for _, id := range item.ComponentIDs {
			if slices.Contains(refs, id) {
				touching = append(touching, item)
				seen[item.ID] = true
				break
			}
		}
	}
	if len(touching) == 0 {
		return nil
	}
	return func(day time.Time) []PublicEvent {
		next := day.Add(24 * time.Hour)
		var out []PublicEvent
		for _, item := range touching {
			start, end := span(item)
			until := now
			if end != nil {
				until = *end
			}
			from, to := start, until
			if day.After(from) {
				from = day
			}
			if next.Before(to) {
				to = next
			}
			if !to.After(from) {
				continue
			}
			out = append(out, PublicEvent{ID: item.ID.String(), Kind: item.Kind, Title: Text{ZH: item.Title, EN: item.Title},
				Impact: item.Impact, Start: start, End: end, Minutes: int(to.Sub(from) / time.Minute)})
		}
		return out
	}
}

func (b *builtPublic) add(entry PublicComponent, status string) {
	b.components = append(b.components, entry)
	if status != StatusUnconfigured {
		b.statuses = append(b.statuses, status)
	}
}

func displayName(name, english string) Text {
	if english == "" {
		english = name
	}
	return Text{ZH: name, EN: english}
}

// buildPublic assembles the page entries: each visible group (with its visible children, after
// it, in order), then the components without a group. A group with no visible child is left out.
func buildPublic(groups []AdminGroup, components []AdminComponent, hist history, incidents []Incident, now time.Time) builtPublic {
	built := builtPublic{components: []PublicComponent{}, visible: map[uuid.UUID]string{}}
	hidden := map[uuid.UUID]bool{}
	for _, group := range groups {
		hidden[group.ID] = group.Hidden
	}
	childrenOf := map[uuid.UUID][]AdminComponent{}
	standalone := []AdminComponent{}
	for _, item := range components {
		switch {
		case item.Hidden:
		case item.GroupID == nil:
			standalone = append(standalone, item)
		case !hidden[*item.GroupID]:
			childrenOf[*item.GroupID] = append(childrenOf[*item.GroupID], item)
		}
	}
	entry := func(item AdminComponent, parent string, refs []uuid.UUID) PublicComponent {
		days, total := hist.series([]uuid.UUID{item.ID}, now, eventsFor(refs, incidents, now))
		return PublicComponent{Key: item.ID.String(), Name: displayName(item.Name, item.NameEN), Status: item.Status, Note: item.Note,
			Parent: parent, Uptime90: total, MonitoringSince: since(days), History: days}
	}
	for _, group := range groups {
		children := childrenOf[group.ID]
		if group.Hidden || len(children) == 0 {
			continue
		}
		key := groupKeyPrefix + group.ID.String()
		built.visible[group.ID] = key
		ids, statuses := []uuid.UUID{}, []string{}
		for _, child := range children {
			ids = append(ids, child.ID)
			if child.Status != StatusUnconfigured {
				statuses = append(statuses, child.Status)
			}
		}
		status := StatusUnconfigured
		if len(statuses) > 0 {
			status = worst(statuses...)
		}
		days, total := hist.series(ids, now, eventsFor(append([]uuid.UUID{group.ID}, ids...), incidents, now))
		built.add(PublicComponent{Key: key, Name: displayName(group.Name, group.NameEN), Status: status, Mode: "group",
			Uptime90: total, MonitoringSince: since(days), History: days}, status)
		for _, child := range children {
			built.visible[child.ID] = child.ID.String()
			built.components = append(built.components, entry(child, key, []uuid.UUID{child.ID, group.ID}))
		}
	}
	for _, item := range standalone {
		built.visible[item.ID] = item.ID.String()
		built.add(entry(item, "", []uuid.UUID{item.ID}), item.Status)
	}
	return built
}

// since is the first day with samples in the window, or empty.
func since(days []PublicDay) string {
	for _, day := range days {
		if day.Sampled > 0 {
			return day.Day
		}
	}
	return ""
}

// publicIncident turns an incident into the public shape: components that are hidden or gone are dropped.
func publicIncident(item Incident, visible map[uuid.UUID]string) PublicIncident {
	keys := []string{}
	for _, id := range item.ComponentIDs {
		if key, found := visible[id]; found {
			keys = append(keys, key)
		}
	}
	updates := make([]PublicUpdate, len(item.Updates))
	for i, update := range item.Updates {
		updates[i] = PublicUpdate{ID: update.ID.String(), Status: update.Status,
			Message: Text{ZH: update.Message, EN: update.Message}, CreatedAt: update.CreatedAt}
	}
	return PublicIncident{ID: item.ID.String(), Kind: item.Kind, Title: Text{ZH: item.Title, EN: item.Title}, Impact: item.Impact,
		Status: item.Status, ComponentKeys: keys, ScheduledStart: item.ScheduledStart, ScheduledEnd: item.ScheduledEnd,
		StartedAt: item.StartedAt, ResolvedAt: item.ResolvedAt, Updates: updates}
}
