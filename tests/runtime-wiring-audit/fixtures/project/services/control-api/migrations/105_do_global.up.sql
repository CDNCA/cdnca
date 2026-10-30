CREATE TABLE public.do_global_static_records (id bigint PRIMARY KEY);
DO $$
BEGIN
  EXECUTE format('CREATE TABLE public.%I (id bigint PRIMARY KEY)', 'do_global_dynamic_records');
END
$$;
