# cdnca ClickHouse migrator for compose and Helm (docs/runbooks/clickhouse-migrate-deploy.md).
# Build from the repository root:
#   docker build -f deploy/clickhouse-migrate/Dockerfile -t cdnca/clickhouse-migrate:<version> .
FROM docker.io/library/python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLICKHOUSE_MIGRATE_MIGRATIONS=/opt/cdnca/clickhouse/migrations

COPY scripts/native-runtime/configure-clickhouse.py scripts/clickhouse-migrate/cdnca-clickhouse-migrate.py /opt/cdnca/clickhouse/
COPY infra/clickhouse/migrations/ /opt/cdnca/clickhouse/migrations/
# Root-owned and read-only for the runtime user; down migrations are not shipped.
RUN rm -f /opt/cdnca/clickhouse/migrations/*.down.sql \
 && chmod -R u=rwX,go=rX /opt/cdnca

USER 65532:65532
ENTRYPOINT ["python3", "-I", "-B", "/opt/cdnca/clickhouse/cdnca-clickhouse-migrate.py"]
CMD ["migrate"]
