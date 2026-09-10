.PHONY: install test run migrate seed lint docker-up docker-down

install:
	pip install -e ".[dev]"

test:
	pytest -v

run:
	uvicorn app.main:app --reload

migrate:
	alembic upgrade head

seed:
	python -m app.db.seed

lint:
	ruff check app tests

docker-up:
	docker compose up --build

docker-down:
	docker compose down
