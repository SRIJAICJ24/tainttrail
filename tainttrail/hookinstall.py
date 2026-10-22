"""`tainttrail install-hooks` / `uninstall-hooks` - edit Claude Code settings safely.

A settings file is someone else's configuration, often with hooks of their own,
so every change here follows the same rules:

  * refuse to touch a file that isn't valid JSON (never "repair" by overwriting)
  * write a timestamped backup next to the file before changing it
  * merge: only TaintTrail's own entries are added or removed; every other hook,
    matcher and setting is left exactly as it was
  * idempotent: running install twice changes nothing the second time, and
    uninstall after install gives back the original settings

TaintTrail's entries are recognised by what they point at - the daemon's
`/hooks/claude-code` URL, or the `tainttrail.hookclient` module - not by position,
so they can be found again after the user reorders the file.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HOOK_PATH = "/hooks/claude-code"
HOOK_MODULE = "tainttrail.hookclient"
EVENTS = ("PreToolUse", "PostToolUse")

KIND_HTTP = "http"
KIND_COMMAND = "command"

SCOPE_USER = "user"
SCOPE_PROJECT = "project"
SCOPE_LOCAL = "local"

# Claude Code's default hook timeout is 600 s. A security hook that hangs for ten
# minutes is worse than none, so TaintTrail's entries always set their own.
DEFAULT_HTTP_TIMEOUT = 5
DEFAULT_COMMAND_TIMEOUT = 10


class HookInstallError(Exception):
    """The settings file can't be changed safely; nothing was written."""


def claude_home() -> Path:
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(override) if override else Path.home() / ".claude"


def settings_path(scope: str = SCOPE_USER, project_dir: str | Path | None = None) -> Path:
    if scope == SCOPE_USER:
        return claude_home() / "settings.json"
    base = Path(project_dir) if project_dir else Path.cwd()
    name = "settings.local.json" if scope == SCOPE_LOCAL else "settings.json"
    return base / ".claude" / name


def handler(kind: str = KIND_HTTP, port: int = 9000, timeout: int | None = None) -> dict[str, Any]:
    """TaintTrail's hook handler object for Claude Code settings."""
    if kind == KIND_HTTP:
        return {"type": "http", "url": f"http://127.0.0.1:{port}{HOOK_PATH}",
                "timeout": timeout or DEFAULT_HTTP_TIMEOUT}
    if kind == KIND_COMMAND:
        # Exec form (`args`): no shell, so an interpreter path with spaces needs
        # no quoting, on every platform.
        return {"type": "command", "command": Path(sys.executable).as_posix(),
                "args": ["-m", HOOK_MODULE], "timeout": timeout or DEFAULT_COMMAND_TIMEOUT}
    raise HookInstallError(f"unknown hook type {kind!r}; use http or command")


#: Exactly the URL `handler("http", port)` writes, for any port.
_OUR_URL = re.compile(r"^http://127\.0\.0\.1:\d{1,5}" + re.escape(HOOK_PATH) + r"$")
#: Pre-rename command hooks (`python -m agentguard.hookclient`) - ours, so an
#: upgrade can replace or remove them. Matched exactly, like the current form.
_LEGACY_MODULE = "agentguard.hookclient"


def is_ours(entry: Any) -> bool:
    """Only the exact handler objects this installer writes count as ours.

    Other tools share this settings file - GoPlus's AgentGuard and momenbasel's
    AgentGuard both register `agentguard ...` hooks - so a substring match on a
    URL path or a module name would remove or replace someone else's hook.
    """
    if not isinstance(entry, dict):
        return False
    kind = entry.get("type")
    if kind == KIND_HTTP:
        return bool(_OUR_URL.match(str(entry.get("url", ""))))
    if kind == KIND_COMMAND:
        return entry.get("args") in (["-m", HOOK_MODULE], ["-m", _LEGACY_MODULE])
    return False


@dataclass
class InstallResult:
    path: Path
    changed: bool
    backup: Path | None = None
    created: bool = False
    message: str = ""


def _load(path: Path) -> tuple[dict[str, Any], bool]:
    """(settings, existed). Raises HookInstallError on anything unsafe to edit."""
    if not path.exists():
        return {}, False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HookInstallError(f"cannot read {path}: {exc}") from exc
    if not text.strip():
        return {}, True
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HookInstallError(
            f"{path} is not valid JSON ({exc}); refusing to edit it. Fix the file "
            f"first - nothing was changed."
        ) from exc
    if not isinstance(data, dict):
        raise HookInstallError(f"{path} does not hold a JSON object; refusing to edit it")
    hooks = data.get("hooks")
    if hooks is not None and not isinstance(hooks, dict):
        raise HookInstallError(f"{path}: 'hooks' is not an object; refusing to edit it")
    return data, True


def _without_ours(settings: dict[str, Any]) -> dict[str, Any]:
    """A copy with every TaintTrail handler removed, and only the groups, events
    and `hooks` key that thereby became empty removed with them."""
    out = copy.deepcopy(settings)
    hooks = out.get("hooks")
    if not isinstance(hooks, dict):
        return out
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept_groups = []
        touched = False
        for group in groups:
            inner = group.get("hooks") if isinstance(group, dict) else None
            if isinstance(inner, list) and any(is_ours(h) for h in inner):
                touched = True
                remaining = [h for h in inner if not is_ours(h)]
                if remaining:
                    kept_groups.append({**group, "hooks": remaining})
                continue
            kept_groups.append(group)
        if touched:
            if kept_groups:
                hooks[event] = kept_groups
            else:
                del hooks[event]
    if not hooks and "hooks" in out and settings.get("hooks") != {}:
        del out["hooks"]
    return out


def _write(path: Path, settings: dict[str, Any], existed: bool) -> Path | None:
    backup = None
    if existed:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(f"{path.name}.tainttrail-backup-{stamp}")
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tainttrail-tmp")
    tmp.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)          # atomic: never a half-written settings file
    return backup


def install(path: Path, *, kind: str = KIND_HTTP, port: int = 9000,
            timeout: int | None = None) -> InstallResult:
    current, existed = _load(path)
    wanted = _without_ours(current)
    hooks = wanted.setdefault("hooks", {})
    entry = handler(kind, port, timeout)
    for event in EVENTS:
        hooks.setdefault(event, []).append({"matcher": "*", "hooks": [dict(entry)]})
    if wanted == current:
        return InstallResult(path, False, message="already installed - nothing changed")
    backup = _write(path, wanted, existed)
    return InstallResult(path, True, backup, created=not existed,
                         message=f"installed {kind} hooks for {', '.join(EVENTS)}")


def uninstall(path: Path) -> InstallResult:
    current, existed = _load(path)
    if not existed:
        return InstallResult(path, False, message="no settings file - nothing to remove")
    wanted = _without_ours(current)
    if wanted == current:
        return InstallResult(path, False, message="no TaintTrail hooks found - nothing changed")
    backup = _write(path, wanted, existed)
    return InstallResult(path, True, backup, message="removed TaintTrail hooks")


def installed(path: Path) -> list[dict[str, Any]]:
    """TaintTrail handlers present in a settings file ([] if none or unreadable)."""
    try:
        data, _ = _load(path)
    except HookInstallError:
        return []
    found = []
    for event, groups in (data.get("hooks") or {}).items():
        for group in groups if isinstance(groups, list) else []:
            for h in (group.get("hooks") or []) if isinstance(group, dict) else []:
                if is_ours(h):
                    found.append({"event": event, **h})
    return found


def hooks_disabled(path: Path) -> bool:
    try:
        data, _ = _load(path)
    except HookInstallError:
        return False
    return bool(data.get("disableAllHooks"))
