package doe

func InsertRecord() string {
	return `INSERT INTO public.do_e_records (id) VALUES ($1)`
}
