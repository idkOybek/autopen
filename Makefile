.PHONY: help build up down logs shell migrate test lint format clean

help:
	@echo "Pentest Automation - Development Commands"
	@echo ""
	@echo "  make build       - Build Docker images"
	@echo "  make up          - Start all services"
	@echo "  make down        - Stop all services"
	@echo "  make logs        - View logs"
	@echo "  make shell       - Open backend shell"
	@echo "  make migrate     - Run database migrations"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Run linters"
	@echo "  make format      - Format code"
	@echo "  make clean       - Clean up containers and volumes"

build:
	docker-compose build

up:
	docker-compose up -d
	@echo "Services started. API docs available at http://localhost/api/docs"

down:
	docker-compose down

logs:
	docker-compose logs -f

shell:
	docker-compose exec backend /bin/bash

migrate:
	docker-compose exec backend alembic upgrade head

migration:
	@read -p "Enter migration message: " msg; \
	docker-compose exec backend alembic revision --autogenerate -m "$$msg"

test:
	docker-compose exec backend pytest

lint:
	docker-compose exec backend flake8 backend/
	docker-compose exec backend mypy backend/

format:
	docker-compose exec backend black backend/

clean:
	docker-compose down -v
	rm -rf backend/__pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

init-db:
	docker-compose exec backend python scripts/init_db.py

celery-worker:
	docker-compose logs -f celery_worker

celery-beat:
	docker-compose logs -f celery_beat

redis-cli:
	docker-compose exec redis redis-cli

psql:
	docker-compose exec postgres psql -U pentest -d pentest_db
