DROP TABLE IF EXISTS public.round13_static_records;
DO $outer$
DECLARE
  dynamic_body text := 'BEGIN DROP TABLE IF EXISTS public.round13_dynamic_records; END';
BEGIN
  EXECUTE format('DO %L', dynamic_body);
END
$outer$;
