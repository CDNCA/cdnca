package lexicaluncertain

func InsertRecord() string {
	return `INSERT INTO public.uncertain_records (id) VALUES ($1)`
}
