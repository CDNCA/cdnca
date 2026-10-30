package doglobalcovered

func InsertRecord() string {
	return `INSERT INTO public.do_global_covered_records (id) VALUES ($1)`
}
