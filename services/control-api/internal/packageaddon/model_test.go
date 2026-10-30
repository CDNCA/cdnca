package packageaddon

import (
	"testing"

	"github.com/google/uuid"
)

func TestValidateAddonCommands(t *testing.T) {
	valid := Command{Action: "product.create", Product: &ProductFields{Name: "Domains", Kind: "domains", Quantity: 2, MonthlyPriceMinor: 123, Enabled: true}}
	if !Valid(valid) {
		t.Fatal("valid product rejected")
	}
	for _, mutate := range []func(*Command){
		func(c *Command) { c.Product.Name = " " }, func(c *Command) { c.Product.Kind = "sql" }, func(c *Command) { c.Product.Quantity = 0 }, func(c *Command) { c.Product.MonthlyPriceMinor = -1 }, func(c *Command) { c.Product.Kind = "waf"; c.Product.Quantity = 2 }, func(c *Command) { c.Product.ProductIDs = []uuid.UUID{uuid.Nil} },
	} {
		copy := *valid.Product
		c := valid
		c.Product = &copy
		mutate(&c)
		if Valid(c) {
			t.Fatalf("invalid accepted: %#v", c)
		}
	}
	for _, action := range []string{"assignment.create", "assignment.update", "assignment.delete", "product.delete"} {
		if Valid(Command{Action: action}) {
			t.Fatalf("missing identity accepted for %s", action)
		}
	}
}
