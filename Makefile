# MicroPKI - Sprint 1
# Run tests: make test

.PHONY: test install

test:
	pytest tests/ -v

install:
	pip install -e .
