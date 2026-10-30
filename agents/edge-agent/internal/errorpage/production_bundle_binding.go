package errorpage

func DecodeProductionBundleBinding(raw []byte) (ProductionBundleBinding, error) {
	document, err := decodeProductionBundle(raw)
	if err != nil || document.Schema != ProductionBundleSchema || !validProductionBinding(document.Binding) {
		return ProductionBundleBinding{}, ErrInvalidProductionBundle
	}
	return document.Binding, nil
}
