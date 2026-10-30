# CACHE-05 static production contract

This driver validates the frozen JetStream resources and the cross-layer source
composition for distributed cache tasks. It is deliberately static: it does not
start PostgreSQL, NATS, Docker, the control API, Gateway, Agent, or OpenResty.

Run once after an affected CACHE-05 code batch:

```sh
tests/cache-distributed-runtime-static/run.sh
```

The later shared infrastructure wave remains responsible for exercising the
same contract against real PostgreSQL and JetStream resources.
