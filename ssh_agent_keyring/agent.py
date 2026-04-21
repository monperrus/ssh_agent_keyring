from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class SignerError(RuntimeError):
    pass


def normalize_public_key(public_key: str) -> str:
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise SignerError("SSH public key must contain at least key type and key data.")
    key_type, key_data = parts[0], parts[1]
    if not (
        key_type.startswith("ssh-")
        or key_type.startswith("ecdsa-")
        or key_type.startswith("sk-")
    ):
        raise SignerError(f"Unsupported SSH public key type: {key_type}")
    return f"{key_type} {key_data}"


class SSHKeygenAgentSigner:
    def _ensure_agent(self) -> None:
        if not os.environ.get("SSH_AUTH_SOCK"):
            raise SignerError("SSH_AUTH_SOCK is not set; ssh-agent is not available.")
        if shutil.which("ssh-add") is None or shutil.which("ssh-keygen") is None:
            raise SignerError("ssh-add and ssh-keygen must both be available in PATH.")

    def list_public_keys(self) -> list[str]:
        self._ensure_agent()
        result = subprocess.run(
            ["ssh-add", "-L"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "ssh-add -L failed"
            raise SignerError(message)
        output = result.stdout.strip()
        if not output or "The agent has no identities." in output:
            return []
        return [normalize_public_key(line) for line in output.splitlines() if line.strip()]

    def sign(self, public_key: str, namespace: str, message: bytes) -> bytes:
        self._ensure_agent()
        normalized = normalize_public_key(public_key)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            key_path = tmpdir_path / "identity.pub"
            message_path = tmpdir_path / "message"
            key_path.write_text(normalized + "\n", encoding="utf-8")
            message_path.write_bytes(message)
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(key_path),
                    "-n",
                    namespace,
                    str(message_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                message = result.stderr.strip() or result.stdout.strip() or "ssh-keygen -Y sign failed"
                raise SignerError(message)
            return Path(str(message_path) + ".sig").read_bytes()
