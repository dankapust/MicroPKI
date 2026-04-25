"""Shared pytest configuration for MicroPKI tests."""
import pytest


def pytest_addoption(parser):
    try:
        parser.addoption(
            "--run-perf", action="store_true", default=False,
            help="Run performance tests (slow, issues 1000 certs)",
        )
    except ValueError:
        pass  # already registered


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-perf", default=False):
        skip_perf = pytest.mark.skip(reason="Need --run-perf option to run")
        for item in items:
            if "perf" in item.keywords:
                item.add_marker(skip_perf)
