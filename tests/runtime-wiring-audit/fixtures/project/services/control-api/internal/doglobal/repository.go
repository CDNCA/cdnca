package doglobal

func InsertStaticRecord() string {
	return `INSERT INTO public.do_global_static_records (id) VALUES ($1)`
}

func InsertDynamicRecord() string {
	return `INSERT INTO public.do_global_dynamic_records (id) VALUES ($1)`
}
