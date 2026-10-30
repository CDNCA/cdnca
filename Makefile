ENV_FILE ?= infra/env/development.env
COMPOSE := docker compose --env-file $(ENV_FILE) -f compose.yaml

.PHONY: help up down status logs infra-up infra-test test-sshd-image test-ssh-install

help:
	@printf '%s\n' \
		'CDNCA development commands:' \
		'  make up          Build and start the complete local stack' \
		'  make down        Stop the complete local stack (persistent data is kept)' \
		'  make status      Show service and health status' \
		'  make logs        Follow the latest service logs' \
		'  make infra-up    Start only PostgreSQL, Redis, ClickHouse, and NATS' \
		'  make infra-test  Start infrastructure and verify each service' \
		'  make test-sshd-image   Build the throwaway sshd image for the SSH install test' \
		'  make test-ssh-install  Run the SSH install integration test (needs TEST_DATABASE_URL)'

up:
	LOCAL_STACK_ENV_FILE="$(ENV_FILE)" ./scripts/local-stack.sh up

down:
	LOCAL_STACK_ENV_FILE="$(ENV_FILE)" ./scripts/local-stack.sh down

status:
	LOCAL_STACK_ENV_FILE="$(ENV_FILE)" ./scripts/local-stack.sh status

logs:
	LOCAL_STACK_ENV_FILE="$(ENV_FILE)" ./scripts/local-stack.sh logs

infra-up:
	$(COMPOSE) up -d --wait

infra-test:
	ENV_FILE="$(ENV_FILE)" ./scripts/infra-test.sh

# SSH remote node install integration test (services/control-api/internal/nodesshinstall).
# The target is a local container started with --rm; no real server is contacted.
SSHD_TEST_IMAGE := cdnca-test-sshd:ge-nodes

test-sshd-image:
	docker build -q -t $(SSHD_TEST_IMAGE) services/control-api/internal/nodesshinstall/testdata/sshd

test-ssh-install: test-sshd-image
	@test -n "$(TEST_DATABASE_URL)" || { echo 'TEST_DATABASE_URL is required' >&2; exit 2; }
	go -C services/control-api test -p 1 -tags integration -count=1 -run TestSSHInstallAgainstRealSSHD ./internal/nodesshinstall/
