"""Send the daily observability digest through Nyxmon's Telegram notifier (``services.obs_daily``).

Runs with Nyxmon's virtualenv Python as the Nyxmon user, with Nyxmon's
environment file (``TELEGRAM_BOT_TOKEN``, ``TELEGRAM_CHAT_ID``), so the digest
takes the same path and credentials as Nyxmon's own alerts and its warning
digest: ``AsyncTelegramNotifier.async_send``, which reports success only once
Telegram acknowledged the message (``ok: true``).

``obs_daily_send.py [--env-file FILE] [--high] < digest.txt`` sends standard
input as one message (silent unless ``--high``). ``--check`` only loads the
notifier and checks that both credentials are set; it sends nothing.
``--env-file`` reads Nyxmon's environment file in this process, which already
runs as the Nyxmon user: systemd's ``EnvironmentFile=`` would open that
Nyxmon-writable path as root.
Exit status: 0 sent (or check passed), 1 Telegram refused or timed out,
2 the notifier is missing or has no credentials.
"""

from __future__ import annotations

import asyncio
import os
import sys


def load_env_file(path: str) -> None:
    """``KEY=VALUE`` lines (``#`` comments, optional ``export`` and quotes) into ``os.environ``."""

    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.removeprefix("export ").split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            os.environ[key.strip()] = value


def main(argv: list[str]) -> int:
    if "--env-file" in argv:
        index = argv.index("--env-file")
        try:
            load_env_file(argv[index + 1])
        except (IndexError, OSError, UnicodeDecodeError) as error:
            print(f"obs-daily-send: environment file unreadable: {type(error).__name__}", file=sys.stderr)
            return 2
        argv = argv[:index] + argv[index + 2 :]
    try:
        from nyxmon.adapters.notification import AsyncTelegramNotifier
    except ImportError as error:
        print(f"obs-daily-send: Nyxmon's notifier is not importable: {error.name}", file=sys.stderr)
        return 2
    notifier = AsyncTelegramNotifier()
    if not notifier.token or not notifier.chat_id:
        print("obs-daily-send: Telegram credentials are missing", file=sys.stderr)
        return 2
    if "--check" in argv:
        print("obs-daily-send: notifier ready")
        return 0
    text = sys.stdin.read()
    if not text.strip():
        print("obs-daily-send: empty digest", file=sys.stderr)
        return 2
    delivered = asyncio.run(notifier.async_send(notifier.escape_markdown_v2(text), high_priority="--high" in argv))
    if delivered is True:
        return 0
    print("obs-daily-send: Telegram did not accept the digest", file=sys.stderr)
    return 2 if delivered is None else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
