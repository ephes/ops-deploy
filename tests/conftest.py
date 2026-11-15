"""Suite-wide fixtures.

pyinfra keeps its current state, inventory, config and host in process-global
context managers. ``ContextManager.use()`` restores the previous module only
when the block exits normally, so a test whose deploy raises leaves its
``State`` (sometimes still executing) installed for every later test in the
same process. With pytest-xdist the tests that run before a file differ per
worker and per run, so such a leak turns into an order-dependent failure.
Each test therefore starts from the context it would see when run alone.

The same holds for the process umask: host programs set ``os.umask(0o077)``
in ``main()``, and a test that runs one in-process would leave it for later
tests, whose ``mkdir()`` then creates ``0700`` directories.

Stub executables written with :func:`tests.stubs.install` share one cache
directory per run (see that module).
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from pyinfra.context import ctx_config, ctx_host, ctx_inventory, ctx_state

from tests import stubs

_CONTEXTS = (ctx_state, ctx_inventory, ctx_config, ctx_host)


@pytest.fixture(autouse=True, scope="session")
def _stub_cache(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    # An xdist worker's base temp is a subdirectory of the run's: share the cache across workers.
    base = tmp_path_factory.getbasetemp()
    stubs.use_cache_dir((base.parent if os.environ.get("PYTEST_XDIST_WORKER") else base) / "stub-cache")
    yield
    stubs.use_cache_dir(None)


@pytest.fixture(autouse=True)
def _isolated_process_state() -> Iterator[None]:
    before = [context.get() for context in _CONTEXTS]
    umask = os.umask(0o022)
    os.umask(umask)
    yield
    for context, module in zip(_CONTEXTS, before, strict=True):
        context.set(module)
    os.umask(umask)
