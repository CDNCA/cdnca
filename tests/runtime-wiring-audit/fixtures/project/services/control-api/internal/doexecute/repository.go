package doexecute

func InsertRecord() string {
	return `INSERT INTO public.do_execute_records (id) VALUES ($1)`
}
