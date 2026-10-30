CREATE TABLE public.do_concat_static_records (id bigint PRIMARY KEY);
DO $$
BEGIN
  EXECUTE 'CREATE TABLE public.' || quote_ident('do_concat_dynamic_records') || ' (id bigint PRIMARY KEY)';
END
$$;
