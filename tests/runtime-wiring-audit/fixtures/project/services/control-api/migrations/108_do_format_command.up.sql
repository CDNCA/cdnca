CREATE TABLE public.do_format_static_records (id bigint PRIMARY KEY);
DO $$
DECLARE
  dynamic_sql text := 'CREATE TABLE public.do_format_dynamic_records (id bigint PRIMARY KEY)';
BEGIN
  EXECUTE format('/* prefix */ %s', dynamic_sql);
END
$$;
