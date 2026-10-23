"""Read-only Minecraft configuration comparison; request content arrives on stdin.

Properties support the generated single-line ASCII key=value subset and the
punctuation/Unicode escaping produced by Java Properties.store. Other syntax
(continuations, whitespace separators, duplicate keys, control escapes) is
explicitly refused. This is deliberately not a general Java properties parser.
"""

import json
import os
import re
import stat
import sys

LABEL = "minecraft-config-state"


class Unsupported(ValueError):
    pass


def decoded(raw):
    result = []
    index = 0
    while index < len(raw):
        character = raw[index]
        index += 1
        if ord(character) != 92:
            result.append(character)
            continue
        if index == len(raw):
            raise Unsupported()
        character = raw[index]
        index += 1
        if character in " :=#!" or ord(character) == 92:
            result.append(character)
        elif character == "u" and re.fullmatch("[0-9a-fA-F]{4}", raw[index : index + 4]):
            result.append(chr(int(raw[index : index + 4], 16)))
            index += 4
        else:
            raise Unsupported()
    return "".join(result)


def properties(text):
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("#", "!")):
            continue
        key, separator, raw = line.partition("=")
        if not separator or not re.fullmatch("[A-Za-z0-9._-]+", key) or key in result:
            raise Unsupported()
        result[key] = decoded(raw)
    return result


def players(text):
    data = json.loads(text)
    if not isinstance(data, list):
        raise Unsupported()
    result = {}
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or item["name"] in result:
            raise Unsupported()
        result[item["name"]] = item
    return result


def equivalent(current, desired, kind):
    if kind == "properties":
        actual, expected = properties(current), properties(desired)
        return all(actual.get(key) == value for key, value in expected.items())
    if kind != "players":
        raise Unsupported()
    actual, expected = players(current), players(desired)
    if set(actual) != set(expected):
        return False
    return all(
        type(actual[name].get(key)) is type(value) and actual[name].get(key) == value
        for name, fields in expected.items()
        for key, value in fields.items()
    )


def inspect(path, desired, kind, mode):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return "pending"
    except PermissionError:
        return "pending"
    except OSError:
        return "unsupported"
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return "unsupported"
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        return "unsupported"
    try:
        same = equivalent(data.decode("ascii"), desired, kind)
    except (ValueError, UnicodeError, TypeError):
        return "unsupported"
    owned = info.st_uid == os.getuid() and info.st_gid == os.getgid()
    return "current" if same and owned and stat.S_IMODE(info.st_mode) == mode else "pending"


if __name__ == "__main__":
    try:
        request = json.load(sys.stdin)
        answer = inspect(sys.argv[1], request["content"], sys.argv[2], int(sys.argv[3], 8))
    except Exception:
        answer = "unsupported"
    print(answer)
