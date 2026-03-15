.PHONY: test lint lint-fix opa-test opa-fmt clean \
       docker-up docker-down docker-build \
       docker-logs docker-restart docker-test \
       docker-shell docker-clean \
       frontend-install frontend-dev frontend-build \
       frontend-lint frontend-test \
       frontend-test-coverage

# ---- Docker Development ----

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker-restart:
	docker compose down && docker compose up -d

docker-test:
	docker compose exec backend pytest -v --cov=app --cov-report=term

docker-shell:
	docker compose exec backend /bin/bash

docker-clean:
	docker compose down -v --rmi local

# ---- Backend (run inside container or local venv) ----

test:
	cd backend && pytest -v --cov=app --cov-report=term

lint:
	cd backend && ruff check app/ tests/

lint-fix:
	cd backend && ruff check --fix app/ tests/

# ---- OPA ----

opa-test:
	opa test policies/ -v

opa-fmt:
	opa fmt --diff policies/

# ---- Frontend Development ----

frontend-install:
	cd frontend && npm install

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build

frontend-lint:
	cd frontend && npm run lint

frontend-test:
	cd frontend && npm test

frontend-test-coverage:
	cd frontend && npm run test:coverage

# ---- Cleanup ----

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null; \
	find . -name "*.pyc" -delete 2>/dev/null; true
