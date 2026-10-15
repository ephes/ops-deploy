"""A minimal recorder checkout and a build runner that fakes the toolchain."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ops_deploy.services.recorder import CommandResult

BINARY = b"\x7fELF recorderd fixture build"


def make_source(root: Path) -> Path:
    source = root / "recorder"
    for path in ("cmd/recorderd/main.go", "web/package.json", "scripts/smoke.sh"):
        (source / path).parent.mkdir(parents=True, exist_ok=True)
        (source / path).write_text("fixture\n")
    return source


@dataclass
class FakeToolchain:
    """Records every controller command; ``go build`` writes ``binary`` to its ``-o`` path."""

    binary: bytes = BINARY
    fail: str | None = None  # first argv word that exits 1
    smoke_rc: int = 0
    calls: list[tuple[list[str], Path, dict[str, str]]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str]) -> CommandResult:
        args = list(argv)
        self.calls.append((args, cwd, dict(env)))
        if self.fail and args[:2] == self.fail.split():
            return CommandResult(1, "", f"{self.fail} broke")
        if args[:2] == ["go", "build"]:
            Path(args[args.index("-o") + 1]).write_bytes(self.binary)
        if args[0].endswith("smoke.sh"):
            return CommandResult(self.smoke_rc, "OK smoke\n", "" if self.smoke_rc == 0 else "SMOKE FAIL: /health")
        return CommandResult(0)
