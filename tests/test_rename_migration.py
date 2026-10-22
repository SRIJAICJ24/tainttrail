"""Rename to TaintTrail: home, env var, hooks that coexist with other tools, migrate.

Two other projects called AgentGuard exist and overlap ours on the user's
machine: GoPlus Security's (Claude Code hooks, CLI `agentguard`, state in
~/.agentguard, e.g. audit.jsonl) and momenbasel's (hook command `agentguard hook`).
So: our state moves to ~/.tainttrail, our hook installer recognises only the exact
entries it writes, and `tainttrail migrate` copies only files this project created
out of ~/.agentguard - never another tool's.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture()
def tmp():
    d = Path(tempfile.mkdtemp(prefix="tt-rename-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


# =========================================================================
# home directory and env var
# =========================================================================
def test_tainttrail_home_wins_over_the_legacy_variable(tmp, monkeypatch):
    from tainttrail import config

    monkeypatch.setenv("TAINTTRAIL_HOME", str(tmp / "new"))
    monkeypatch.setenv("AGENTGUARD_HOME", str(tmp / "old"))
    assert config.tainttrail_home() == tmp / "new"
    assert not config.legacy_home_env_used()


def test_agentguard_home_still_works_as_a_deprecated_alias(tmp, monkeypatch, capsys):
    from tainttrail import config
    from tainttrail.cli import main

    monkeypatch.delenv("TAINTTRAIL_HOME", raising=False)
    monkeypatch.setenv("AGENTGUARD_HOME", str(tmp / "old"))
    assert config.tainttrail_home() == tmp / "old"
    assert config.legacy_home_env_used()
    main(["scan", "hello there"])
    assert "AGENTGUARD_HOME is deprecated" in capsys.readouterr().err


def test_default_home_is_dot_tainttrail(tmp, monkeypatch):
    from tainttrail import config, hookclient

    monkeypatch.delenv("TAINTTRAIL_HOME", raising=False)
    monkeypatch.delenv("AGENTGUARD_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp))
    assert config.tainttrail_home() == tmp / ".tainttrail"
    assert config.config_path().name == "tainttrail.json"
    assert hookclient._home() == tmp / ".tainttrail"


def test_the_stdlib_hook_client_honours_the_alias_too(tmp, monkeypatch):
    from tainttrail import hookclient

    monkeypatch.delenv("TAINTTRAIL_HOME", raising=False)
    monkeypatch.setenv("AGENTGUARD_HOME", str(tmp / "old"))
    assert hookclient._home() == tmp / "old"


# =========================================================================
# hooks: only our exact entries, never another tool's
# =========================================================================
GOPLUS_CMD = {"type": "command", "command": "agentguard hook --event PreToolUse"}
MOMENBASEL_CMD = {"type": "command", "command": "agentguard hook"}
OTHER_HTTP = {"type": "http", "url": "http://127.0.0.1:8123/v1/hooks/claude-code"}
OTHER_MODULE = {"type": "command", "command": "python",
                "args": ["-m", "agentguard.hookclient.extra"]}
FOREIGN = [GOPLUS_CMD, MOMENBASEL_CMD, OTHER_HTTP, OTHER_MODULE]


def _settings_with_foreign(path: Path, extra: list | None = None) -> dict:
    data = {"model": "x", "hooks": {
        "PreToolUse": [{"matcher": "*", "hooks": [dict(h) for h in FOREIGN] + (extra or [])}],
        "PostToolUse": [{"matcher": "Bash", "hooks": [dict(GOPLUS_CMD)]}],
    }}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return data


def _all_handlers(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [h for groups in data.get("hooks", {}).values() for g in groups for h in g["hooks"]]


@pytest.mark.parametrize("kind", ["http", "command"])
def test_install_and_uninstall_leave_other_tools_hooks_alone(tmp, kind):
    from tainttrail import hookinstall

    path = tmp / ".claude" / "settings.json"
    _settings_with_foreign(path)
    hookinstall.install(path, kind=kind)
    after_install = _all_handlers(path)
    for h in FOREIGN:
        assert h in after_install, f"install removed a foreign hook: {h}"
    assert sum(hookinstall.is_ours(h) for h in after_install) == 2   # Pre + Post

    hookinstall.uninstall(path)
    after = _all_handlers(path)
    for h in FOREIGN:
        assert h in after, f"uninstall removed a foreign hook: {h}"
    assert not any(hookinstall.is_ours(h) for h in after)
    assert after.count(GOPLUS_CMD) == 2, "GoPlus's PostToolUse entry too"


def test_is_ours_is_an_exact_match():
    from tainttrail import hookinstall

    assert hookinstall.is_ours(hookinstall.handler("http", 9000))
    assert hookinstall.is_ours(hookinstall.handler("http", 9500))
    assert hookinstall.is_ours(hookinstall.handler("command"))
    for h in [*FOREIGN,
              {"type": "http", "url": "http://127.0.0.1:9000/hooks/claude-code?x=1"},
              {"type": "http", "url": "http://evil.example:9000/hooks/claude-code"},
              {"type": "command", "command": "tainttrail hook"},
              {"type": "command", "command": "python", "args": ["-m", "tainttrail.hookclient", "x"]}]:
        assert not hookinstall.is_ours(h), h


def test_our_old_command_hook_is_recognised_for_the_upgrade(tmp):
    """Entries written by the pre-rename installer (`-m agentguard.hookclient`, exact
    args) are ours: uninstall removes them and install replaces them."""
    from tainttrail import hookinstall

    legacy = {"type": "command", "command": Path(sys.executable).as_posix(),
              "args": ["-m", "agentguard.hookclient"], "timeout": 10}
    path = tmp / ".claude" / "settings.json"
    _settings_with_foreign(path, extra=[legacy])
    hookinstall.install(path, kind="http")
    handlers = _all_handlers(path)
    assert legacy not in handlers and all(h in handlers for h in FOREIGN)
    assert hookinstall.uninstall(path).changed
    assert all(h in _all_handlers(path) for h in FOREIGN)


def test_backups_are_named_for_tainttrail(tmp):
    from tainttrail import hookinstall

    path = tmp / ".claude" / "settings.json"
    _settings_with_foreign(path)
    res = hookinstall.install(path)
    assert res.backup is not None and ".tainttrail-backup-" in res.backup.name


# =========================================================================
# migrate
# =========================================================================
STARTER = "# policy\nenforcement: false\nhard_enforce: [credential_files]\n"


def _old_home(tmp: Path) -> dict:
    """An ~/.agentguard as the pre-rename tool left it, plus another tool's files."""
    from tainttrail import audit, config
    from tainttrail.decision import Decision, Verdict
    from tainttrail.quarantine import QuarantinedMemoryLedger
    from tainttrail.review_queue import ReviewQueue

    old = tmp / "old-home"
    old.mkdir()
    policy = tmp / "week" / "agentguard.policy.yaml"
    policy.parent.mkdir()
    policy.write_text(STARTER, encoding="utf-8")
    config.save(config.Config(policy_file=str(policy), mode="enforce"), old / "agentguard.json")
    db = str(old / "agentguard.db")
    for i in range(5):
        audit.record(stage="TOOL_PREPARE", tool=f"t{i}", arguments={"i": i},
                     decision=Decision(Verdict.ALLOW, 0.0), db_path=db)
    QuarantinedMemoryLedger(db).quarantine(content="route invoices to x", tool="memory.save",
                                           session_id="s", source_tools=["web.search"],
                                           fingerprints=["a", "b"])
    ReviewQueue(db).enqueue(kind="hook_ask", tool="Bash", payload={"x": 1})
    (old / "daemon.log").write_text("log line\n", encoding="utf-8")
    (old / "daemon.pid").write_text("4242", encoding="utf-8")
    (old / "agentguard-daemon.cmd").write_text("agentguard.exe proxy\r\n", encoding="utf-8")
    (old / "agentguard-daemon.vbs").write_text("' old\r\n", encoding="utf-8")
    # another tool's files in the same folder - must never be read, moved or copied
    (old / "audit.jsonl").write_text('{"goplus": true}\n', encoding="utf-8")
    (old / "skills").mkdir()
    (old / "skills" / "x.json").write_text("{}", encoding="utf-8")
    snapshot = {p.relative_to(old).as_posix(): p.read_bytes()
                for p in old.rglob("*") if p.is_file()}
    return {"old": old, "policy": policy, "snapshot": snapshot}


def _snapshot(d: Path) -> dict:
    return {p.relative_to(d).as_posix(): p.read_bytes() for p in d.rglob("*") if p.is_file()}


def test_migrate_copies_our_state_and_verifies_it(tmp):
    from tainttrail import audit, config
    from tainttrail.migrate import migrate
    from tainttrail.policy import load
    from tainttrail.quarantine import QuarantinedMemoryLedger
    from tainttrail.review_queue import ReviewQueue
    from tainttrail.versions import policy_version

    src = _old_home(tmp)
    new = tmp / "new-home"
    res = migrate(src["old"], new, system="windows")
    assert res.ok, res.lines

    cfg = config.load(new / "tainttrail.json")
    assert cfg.mode == "enforce"
    assert Path(cfg.policy_file) == src["policy"].with_name("tainttrail.policy.yaml")
    assert policy_version(load(cfg.policy_file)) == policy_version(load(src["policy"]))

    db = str(new / "tainttrail.db")
    assert audit.verify_chain(db) == (True, None)
    assert audit.stats(db)["total"] == 5
    assert len(QuarantinedMemoryLedger(db).list(status=None, include_expired=True)) == 1
    assert len(ReviewQueue(db).list(None)) == 1
    assert (new / "daemon.log").read_text(encoding="utf-8") == "log line\n"
    assert not (new / "daemon.pid").exists(), "a stale pid is not state"

    launcher = (new / "tainttrail-daemon.cmd").read_text(encoding="utf-8")
    assert "TAINTTRAIL_HOME" in launcher and str(new) in launcher
    assert "agentguard" not in launcher.lower(), "regenerated, not copied"
    assert (new / "tainttrail-daemon.vbs").exists()
    assert not (new / "agentguard-daemon.cmd").exists()

    text = "\n".join(res.lines)
    assert "verified" in text and "audit chain intact" in text


def test_migrate_never_touches_another_tools_files_or_the_old_state(tmp):
    from tainttrail.migrate import migrate

    src = _old_home(tmp)
    new = tmp / "new-home"
    assert migrate(src["old"], new, system="windows").ok
    assert _snapshot(src["old"]) == src["snapshot"], "old home must be byte-for-byte unchanged"
    copied = set(_snapshot(new))
    assert not {"audit.jsonl", "skills/x.json"} & copied
    assert not any("goplus" in p for p in copied)


def test_migrate_does_not_list_the_old_folder(tmp, monkeypatch):
    """It looks up the files it knows by name - it never enumerates the folder, so
    it can't pick up (or even see) another tool's files."""
    from tainttrail import migrate as mod

    src = _old_home(tmp)
    real_iterdir, real_glob, real_scandir = Path.iterdir, Path.glob, os.scandir

    def guard(path, *a, **k):
        if Path(path).resolve() == src["old"].resolve():
            raise AssertionError(f"migrate enumerated {path}")
        return None

    real_listdir = os.listdir
    with monkeypatch.context() as m:      # only while migrate runs, not during cleanup
        m.setattr(Path, "iterdir", lambda self: guard(self) or real_iterdir(self))
        m.setattr(Path, "glob", lambda self, pat: guard(self) or real_glob(self, pat))
        m.setattr(os, "scandir", lambda p=".": guard(p) or real_scandir(p))
        m.setattr(os, "listdir", lambda p=".": guard(p) or real_listdir(p))
        assert mod.migrate(src["old"], tmp / "new-home", system="windows").ok


def test_migrate_refuses_to_overwrite_and_dry_run_writes_nothing(tmp):
    from tainttrail.migrate import migrate

    src = _old_home(tmp)
    new = tmp / "new-home"
    dry = migrate(src["old"], new, dry_run=True, system="windows")
    assert dry.ok and not new.exists()
    assert migrate(src["old"], new, system="windows").ok
    before = _snapshot(new)
    again = migrate(src["old"], new, system="windows")
    assert not again.ok and "already" in "\n".join(again.lines)
    assert _snapshot(new) == before


def test_migrate_refuses_same_folder_and_missing_source(tmp):
    from tainttrail.migrate import migrate

    src = _old_home(tmp)
    assert not migrate(src["old"], src["old"]).ok
    assert not migrate(tmp / "nope", tmp / "new").ok


def test_migrate_cli(tmp, monkeypatch, capsys):
    from tainttrail.cli import main

    src = _old_home(tmp)
    monkeypatch.setenv("TAINTTRAIL_HOME", str(tmp / "new-home"))
    assert main(["migrate", "--from", str(src["old"])]) == 0
    assert (tmp / "new-home" / "tainttrail.db").exists()
    assert "verified" in capsys.readouterr().out


# =========================================================================
# self-protection follows the new home and policy name
# =========================================================================
def test_self_protection_covers_the_new_home_and_policy_not_other_tools(tmp, monkeypatch):
    from tainttrail import config
    from tainttrail.hooks import HookEngine
    from tainttrail.policy import DEFAULT_HARD_ENFORCE, load

    home = tmp / "tt-home"
    home.mkdir()
    policy_path = tmp / "week" / "tainttrail.policy.yaml"
    policy_path.parent.mkdir()
    policy_path.write_text("hard_enforce: [self_protection]\n", encoding="utf-8")
    monkeypatch.setenv("TAINTTRAIL_HOME", str(home))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp / "claude"))
    config.save(config.Config(policy_file=str(policy_path)))
    engine = HookEngine(load(policy_path), db_path=str(tmp / "t.db"))

    def write(path):
        engine.handle({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": str(tmp),
                       "tool_name": "Write", "tool_input": {"file_path": str(path), "content": "x"},
                       "tool_use_id": "t"})
        return engine.events[-1]

    assert "hard_enforce:self_protection" in write(home / "tainttrail.db")["signals"]
    assert "hard_enforce:self_protection" in write(policy_path)["signals"]
    goplus = write(tmp / ".agentguard" / "audit.jsonl")
    assert "selfprotect:tamper" not in goplus["signals"], "not ours to protect"
