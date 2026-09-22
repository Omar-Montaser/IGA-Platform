"""How the connector reaches the target system.

Three transports, one interface. Discovery and remediation are written against
the interface, so the same parsing and the same guards apply whichever is in use.

    SSHTransport      agentless - the standard IGA pattern. The connector runs
                      wherever Module 4 runs and reaches the target over SSH.
    LocalTransport    agent-based - the connector runs on the target itself.
    FixtureTransport  reads a captured samples/ directory. No VM, no network,
                      so the parser is unit-testable in CI.

Commands are always a list of arguments, never a shell string, so nothing built
from discovered data can be reinterpreted by a shell.
"""
import json
import os
import shlex
import subprocess


class TransportError(RuntimeError):
    pass


# ---------------------------------------------------------------- agentless
class SSHTransport:
    """Reaches the target over SSH. Host keys are verified, never auto-added."""

    def __init__(self, host, port=22, username="iga_svc", key_path=None,
                 known_hosts=None, timeout=15):
        import paramiko  # imported lazily so the fixture path needs no paramiko

        self.host, self.port, self.username = host, int(port), username
        self.timeout = timeout
        self._client = paramiko.SSHClient()

        known = known_hosts or os.path.expanduser("~/.ssh/known_hosts")
        if os.path.isfile(known):
            self._client.load_host_keys(known)
        # RejectPolicy, not AutoAddPolicy: an unknown host key means the target
        # is not the machine we were told to review, and that is a hard stop.
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            self._client.connect(
                hostname=host, port=self.port, username=username,
                key_filename=key_path, timeout=timeout,
                allow_agent=False, look_for_keys=key_path is None,
            )
        except Exception as exc:
            raise TransportError(f"SSH connection to {username}@{host}:{port} "
                                 f"failed: {exc}") from exc

    def run(self, args):
        command = " ".join(shlex.quote(a) for a in args)
        try:
            _stdin, stdout, stderr = self._client.exec_command(
                command, timeout=self.timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            return stdout.channel.recv_exit_status(), out, err
        except Exception as exc:
            raise TransportError(f"SSH command failed: {exc}") from exc

    def close(self):
        self._client.close()

    def describe(self):
        return f"ssh://{self.username}@{self.host}:{self.port}"


# -------------------------------------------------------------- agent-based
class LocalTransport:
    """Runs on the target itself."""

    def run(self, args):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
            return r.returncode, r.stdout, r.stderr
        except (OSError, subprocess.SubprocessError) as exc:
            raise TransportError(f"local command failed: {exc}") from exc

    def close(self):
        pass

    def describe(self):
        return "local"


# ------------------------------------------------------------------ fixture
class FixtureTransport:
    """Serves a captured samples/ directory. Explicitly not a live system."""

    def __init__(self, directory):
        self.dir = directory
        for name in ("passwd", "group"):
            if not os.path.isfile(os.path.join(directory, name)):
                raise TransportError(f"fixture directory is missing {name}: {directory}")

    def run(self, args):
        if args[:2] == ["getent", "passwd"]:
            return 0, open(os.path.join(self.dir, "passwd")).read(), ""
        if args[:2] == ["getent", "group"]:
            return 0, open(os.path.join(self.dir, "group")).read(), ""
        if args[-1] == "sudo" and "iga-inspect" in " ".join(args):
            path = os.path.join(self.dir, "sudoers_dropins.json")
            return 0, (open(path).read() if os.path.isfile(path) else "{}"), ""
        # A fixture is read-only by construction: it can never change a system.
        return 1, json.dumps({"ok": False, "error": "fixture_is_read_only"}), ""

    def close(self):
        pass

    def describe(self):
        return f"fixture://{self.dir}"


def from_env(env=None):
    """Build the configured transport. IGA_TRANSPORT selects ssh|local|fixture."""
    env = env or os.environ
    kind = env.get("IGA_TRANSPORT", "local").lower()
    if kind == "ssh":
        host = env.get("IGA_SSH_HOST")
        if not host:
            raise TransportError("IGA_TRANSPORT=ssh requires IGA_SSH_HOST")
        return SSHTransport(
            host=host,
            port=env.get("IGA_SSH_PORT", 22),
            username=env.get("IGA_SSH_USER", "iga_svc"),
            key_path=env.get("IGA_SSH_KEY"),
            known_hosts=env.get("IGA_SSH_KNOWN_HOSTS"),
        )
    if kind == "fixture":
        return FixtureTransport(env.get("IGA_FIXTURE_DIR", "./samples"))
    if kind == "local":
        return LocalTransport()
    raise TransportError(f"unknown IGA_TRANSPORT: {kind}")
