package site

// rumCreateValue is the rum_sample_percent of a new site: off
// unless the request sets it.
func rumCreateValue(fields SiteFields) *int {
	if !fields.RUMSet {
		return nil
	}
	return fields.RUMSamplePercent
}

func sameRUMSamplePercent(a, b *int) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// ValidRUMSamplePercent: nil (off) or 1-100.
func ValidRUMSamplePercent(value *int) bool {
	return value == nil || *value >= 1 && *value <= 100
}
