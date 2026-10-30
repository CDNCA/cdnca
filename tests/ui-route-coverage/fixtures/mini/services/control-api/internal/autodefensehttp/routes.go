package autodefensehttp

var routes = []route{
	{method: http.MethodGet, segments: []string{"sites"}, tenant: true, serve: (*Handler).listSites},
}
