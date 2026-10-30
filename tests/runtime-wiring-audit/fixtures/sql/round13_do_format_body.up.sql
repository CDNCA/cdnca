CREATE TABLE public.round13_static_records (id bigint PRIMARY KEY);
DO $outer$
DECLARE
  dynamic_body text := 'BEGIN CREATE TABLE public.round13_dynamic_records (id bigint PRIMARY KEY); END';
BEGIN
  EXECUTE format('DO %L', dynamic_body);
END
$outer$;
