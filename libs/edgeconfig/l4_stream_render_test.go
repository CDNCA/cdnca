package edgeconfig

// buildStreams renders an L4-only spec the way a site runtime v2 document
// carries its streams (RenderStreamFragment: the signed L4 v2 artifact) and
// returns it as the files of a bundle.
func buildStreams(spec Spec) (Bundle, error) {
	_, files, err := RenderStreamFragment(spec.ConfigVersionID, spec.ConfigRevision,
		StreamRuntime{TenantID: spec.TenantID, StreamsV2: spec.L4StreamsV2}, []uint16{spec.HealthPort})
	if err != nil {
		return Bundle{}, err
	}
	if files == nil {
		files = map[string][]byte{}
	}
	files["site-runtime.v2.json"] = []byte("{}\n")
	return newBundle(files)
}
