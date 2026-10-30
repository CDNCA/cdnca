package doconcat

func InsertStaticRecord() string {
	return `INSERT INTO public.do_concat_static_records (id) VALUES ($1)`
}

func InsertDynamicRecord() string {
	return `INSERT INTO public.do_concat_dynamic_records (id) VALUES ($1)`
}
