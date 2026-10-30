CREATE TABLE public.do_global_covered_records (id bigint PRIMARY KEY);
DO $$
BEGIN
  EXECUTE format('CREATE TABLE public.%I (id bigint PRIMARY KEY)', 'unrelated_dynamic_records');
END
$$;
