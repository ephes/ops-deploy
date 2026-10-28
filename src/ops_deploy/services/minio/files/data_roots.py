"""Read-only first-mismatch ownership probe; never read object bodies or fix descendants."""
import grp
import json
import os
import pwd
import stat
import sys


def inspect(roots, user, group):
    existing = []
    for root in roots:
        try:
            info = os.lstat(root)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("data root is not a real directory")
        existing.append((root, info.st_dev))
    if not existing:
        return False
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        for root, _ in existing:
            with os.scandir(root) as entries:
                if next(entries, None) is not None:
                    raise ValueError("existing data requires the configured account identity") from None
        return False
    populated = False
    for root, device in existing:
        # Exclude the root itself: deployment owns its top-level owner/mode.
        pending = [root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    populated = True
                    info = entry.stat(follow_symlinks=False)
                    if info.st_dev != device:
                        raise ValueError("nested mount below data root is outside deployment ownership")
                    if info.st_uid != uid or info.st_gid != gid:
                        raise ValueError("foreign-owned descendant below data root; no recursive repair performed")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(entry.path)
    return populated


def main():
    try:
        payload = json.load(sys.stdin)
        populated = inspect(payload["roots"], payload["user"], payload["group"])
        print("current" if populated else "empty")
    except ValueError as error:
        print("refused: " + str(error))
        sys.exit(1)
    except Exception:
        print("refused: unable to inspect data root ownership")
        sys.exit(1)


if __name__ == "__main__":
    main()
