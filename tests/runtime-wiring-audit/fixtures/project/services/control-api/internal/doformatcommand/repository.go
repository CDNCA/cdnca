package doformatcommand

func InsertStaticRecord() string {
	return `INSERT INTO public.do_format_static_records (id) VALUES ($1)`
}

func InsertDynamicRecord() string {
	return `INSERT INTO public.do_format_dynamic_records (id) VALUES ($1)`
}
