"""Native discovery: read the Linux access landscape. No judgement, no mapping.

Everything this module returns is Linux-shaped. Converting it into generic
objects is `normalize.py`'s job, and nothing above that boundary sees these
structures.

Reads go through `getent` rather than the local `pwd`/`grp` modules, so the same
parsing runs whether the target is reached over SSH, locally, or from a captured
fixture. One code path, one set of tests.
"""
import json
from dataclasses import dataclass, field

INSPECT = "/usr/local/sbin/iga-inspect"
SYSTEM_UID_FLOOR = 1000
DISABLED_SHELLS = ("nologin", "false", "sync")


class DiscoveryError(RuntimeError):
    """The target system could not be read completely."""


@dataclass
class NativeAccount:
    username: str
    uid: int
    gid: int
    gecos: str
    shell: str
    primary_group: str
    groups: list = field(default_factory=list)   # secondary POSIX group names
    sudo_lines: list = field(default_factory=list)

    @property
    def enabled(self):
        """Disabled means the login shell denies login.

        The password field is deliberately not used: accounts provisioned
        without a password read as locked to `passwd -S` while being active.
        """
        return not self.shell.endswith(DISABLED_SHELLS)


def parse_passwd(text):
    """name:passwd:uid:gid:gecos:home:shell"""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) != 7 or not parts[0] or not parts[2].isdigit() or not parts[3].isdigit():
            raise DiscoveryError('Malformed passwd record; refusing incomplete discovery.')
        rows.append({"username": parts[0], "uid": int(parts[2]), "gid": int(parts[3]),
                     "gecos": parts[4].split(",")[0], "shell": parts[6]})
    if len({r['username'] for r in rows}) != len(rows) or len({r['uid'] for r in rows}) != len(rows):
        raise DiscoveryError('Ambiguous account name or UID in passwd enumeration.')
    return rows


def parse_group(text):
    """name:passwd:gid:member,member"""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) != 4 or not parts[0] or not parts[2].isdigit():
            raise DiscoveryError('Malformed group record; refusing incomplete discovery.')
        members = [m for m in parts[3].split(",") if m]
        rows.append({"name": parts[0], "gid": int(parts[2]), "members": members})
    if len({r['name'] for r in rows}) != len(rows) or len({r['gid'] for r in rows}) != len(rows):
        raise DiscoveryError('Ambiguous group name or GID in group enumeration.')
    return rows


def _getent(transport, database):
    rc, out, err = transport.run(["getent", database])
    # Enumeration must succeed completely; partial rows cannot prove absence.
    if rc != 0 or not out.strip():
        raise DiscoveryError(f"could not read {database}: {err.strip() or f'exit {rc}'}")
    return out


def _sudo_grants(transport):
    rc, out, err = transport.run(["sudo", "-n", INSPECT, "sudo"])
    if rc != 0:
        raise DiscoveryError(
            f"privileged sudo inspection failed: {err.strip() or f'exit {rc}'}")
    try:
        result = json.loads(out)
        if not isinstance(result, dict) or any(
                not isinstance(name, str) or not isinstance(lines, list)
                or not all(isinstance(line, str) and not line.startswith('<unreadable:') for line in lines)
                for name, lines in result.items()):
            raise ValueError('Invalid or incomplete sudo inspection')
        return result
    except ValueError as exc:
        raise DiscoveryError(f"iga-inspect returned invalid JSON: {exc}") from exc


def discover(transport, managed_groups):
    """Return native accounts in scope.

    `managed_groups` bounds what is reported: a POSIX group outside the mapping
    is not this connector's business and is left for another scan to describe.
    """
    managed = set(managed_groups)

    groups = parse_group(_getent(transport, "group"))
    gid_to_name = {g["gid"]: g["name"] for g in groups}
    members = {}
    for g in groups:
        if g["name"] in managed:
            for m in g["members"]:
                members.setdefault(m, set()).add(g["name"])

    sudo = _sudo_grants(transport)

    accounts = []
    for row in parse_passwd(_getent(transport, "passwd")):
        if row["uid"] < SYSTEM_UID_FLOOR or row["username"] == "nobody":
            continue
        primary = gid_to_name.get(row["gid"], str(row["gid"]))
        held = set(members.get(row["username"], set()))
        # A managed group held as the PRIMARY group is still access. The lab
        # never creates that shape, but a real system can, and dropping it
        # would silently under-report.
        if primary in managed:
            held.add(primary)
        accounts.append(NativeAccount(
            username=row["username"], uid=row["uid"], gid=row["gid"],
            gecos=row["gecos"], shell=row["shell"], primary_group=primary,
            groups=sorted(held), sudo_lines=sudo.get(row["username"], []),
        ))

    return sorted(accounts, key=lambda a: a.uid)
