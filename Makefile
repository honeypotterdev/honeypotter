test:
	uv run pytest tests -vv --cov=src --cov-report=term-missing

lint:
	uv run ruff check

format:
	uv run ruff format
	uv run ruff check --fix
