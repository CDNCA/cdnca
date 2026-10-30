package securitypolicy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// refuse is ErrInvalidInput naming the refused field: a JSON path relative
// to the value being checked, prefixed up to the request body by the caller
// (fielderr.Within): rules[1].conditions[0].values.
func refuse(field, reason string) error {
	return fielderr.New(ErrInvalidInput, field, reason)
}

// unlocated drops the field of a refusal of values the client did not send
// (generated, stored or copied policies): the path would name another body.
func unlocated(err error) error {
	if _, ok := fielderr.As(err); ok {
		return ErrInvalidInput
	}
	return err
}

// unlocatedRules drops the field of a refusal inside rules (rules[n]...),
// for rule lists that are not the list the client sent.
func unlocatedRules(err error) error {
	if located, ok := fielderr.As(err); ok && strings.HasPrefix(located.Field, "rules") {
		return ErrInvalidInput
	}
	return err
}

type bound struct {
	field string
	ok    bool
}

// outOfRange refuses the first bound that does not hold.
func outOfRange(bounds ...bound) error {
	for _, item := range bounds {
		if !item.ok {
			return refuse(item.field, fielderr.OutOfRange)
		}
	}
	return nil
}

func within(value, minimum, maximum int) bool { return value >= minimum && value <= maximum }

func indexed(name string, index int) string { return fmt.Sprintf("%s[%d]", name, index) }

// requestOrder is, for each position sortRules will give a rule, the index
// it has in rules (the request): checks run on sorted rules name it as sent.
func requestOrder(rules []Rule) []int {
	order := make([]int, len(rules))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(left, right int) bool {
		a, b := rules[order[left]], rules[order[right]]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.ID.String() < b.ID.String()
	})
	return order
}

// rulePath is rules[n] of the sorted rule at position, n as sent (order nil:
// position itself).
func rulePath(order []int, position int) string {
	if order != nil {
		position = order[position]
	}
	return indexed("rules", position)
}
