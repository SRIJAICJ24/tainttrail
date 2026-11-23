"""`tainttrail setup` / `tainttrail uninstall`: the whole install in one command.

Before: onboard, install-hooks, onboard --install-daemon --activate (which needs
Administrator rights on Windows for schtasks), doctor - four steps, one of which
failed on the author's machine. `setup` does it in one, without admin rights;
`uninstall` reverses it and keeps the audit data. No real process is started in
these tests: the process runner, the detached spawner and the health probe are
injected.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

GOPLUS = {"type": "command", "command": "agentguard hook"}


@pytest.fixture()
def machine(monkeypatch):
    root = Path(tempfile.mkdtemp(prefix="tt-setup-"))
    home = root / "user"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("TAINTTRAIL_HOME", raising=False)
    monkeypatch.delenv("AGENTGUARD_HOME", raising=False)
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude"))
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [dict(GOPLUS)]}]}}), encoding="utf-8")
    calls = {"run": [], "spawn": []}
    state = {"up": False}

    def runner(argv, **_kw):
        calls["run"].append(list(argv))
        if argv[:2] == ["systemctl", "--user"] or argv[:1] == ["launchctl"]:
            state["up"] = True

        class R:
            returncode = 0
            stdout = stderr = ""
        return R()

    def spawn(argv):
        calls["spawn"].append(list(argv))
        state["up"] = True

    def probe(port, timeout=1.0):
        from tainttrail import __version__
        return {"ok": True, "service": "tainttrail", "version": __version__} if state["up"] else None

    yield {"home": home, "settings": settings, "calls": calls, "state": state,
           "kw": {"runner": runner, "spawn": spawn, "probe": probe,
                  "sleep": lambda s: None, "port_free": lambda p: True}}
    shutil.rmtree(root, ignore_errors=True)


def _hooks(settings: Path) -> list[dict]:
    data = json.loads(settings.read_text(encoding="utf-8"))
    return [h for gs in data.get("hooks", {}).values() for g in gs for h in g["hooks"]]


def test_setup_on_windows_does_everything_without_admin(machine):
    from tainttrail import config, hookinstall
    from tainttrail.installer import setup

    res = setup(system="windows", **machine["kw"])
    assert res.ok, res.lines
    home = machine["home"] / ".tainttrail"
    conf = config.load(home / "tainttrail.json")
    assert conf.mode == "observe"
    assert Path(conf.policy_file) == home / "tainttrail.policy.yaml"
    assert (home / "tainttrail.policy.yaml").is_file()
    hooks = _hooks(machine["settings"])
    assert sum(hookinstall.is_ours(h) for h in hooks) == 2 and GOPLUS in hooks
    vbs = home / "tainttrail-daemon.vbs"
    assert vbs.is_file()
    startup = machine["home"] / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    assert (startup / "tainttrail-daemon.vbs").read_text(encoding="utf-8") == \
        vbs.read_text(encoding="utf-8")
    assert machine["calls"]["spawn"] == [["wscript.exe", str(vbs)]]
    assert not any("schtasks" in c[0] for c in machine["calls"]["run"]), "no admin needed"
    assert "protected" in "\n".join(res.lines).lower()


def test_setup_is_idempotent(machine):
    from tainttrail import hookinstall
    from tainttrail.installer import setup

    assert setup(system="windows", **machine["kw"]).ok
    policy = machine["home"] / ".tainttrail" / "tainttrail.policy.yaml"
    policy.write_text(policy.read_text(encoding="utf-8") + "\n# my edit\n", encoding="utf-8")
    res = setup(system="windows", **machine["kw"])
    assert res.ok
    assert "# my edit" in policy.read_text(encoding="utf-8"), "never overwrites a policy"
    assert sum(hookinstall.is_ours(h) for h in _hooks(machine["settings"])) == 2
    assert len(machine["calls"]["spawn"]) == 1, "already running: not started twice"


def test_setup_enforce_flag(machine):
    from tainttrail import config
    from tainttrail.installer import setup

    assert setup(system="windows", enforce=True, **machine["kw"]).ok
    assert config.load(machine["home"] / ".tainttrail" / "tainttrail.json").mode == "enforce"


@pytest.mark.parametrize("system,expect", [
    ("linux", ["systemctl", "--user", "enable", "--now", "tainttrail"]),
    ("darwin", ["launchctl", "load", "-w"]),
])
def test_setup_on_linux_and_macos_uses_the_user_service_manager(machine, system, expect):
    from tainttrail.installer import setup

    res = setup(system=system, **machine["kw"])
    assert res.ok, res.lines
    assert any(c[:len(expect)] == expect for c in machine["calls"]["run"]), machine["calls"]


def test_setup_refuses_to_start_over_an_unmigrated_agentguard_install(machine):
    from tainttrail.installer import setup

    old = machine["home"] / ".agentguard"
    old.mkdir()
    (old / "agentguard.json").write_text("{}", encoding="utf-8")
    (old / "audit.jsonl").write_text("goplus\n", encoding="utf-8")
    res = setup(system="windows", **machine["kw"])
    assert not res.ok and "tainttrail migrate" in "\n".join(res.lines)
    assert not (machine["home"] / ".tainttrail").exists()
    assert (old / "audit.jsonl").read_text(encoding="utf-8") == "goplus\n"


def test_setup_does_not_start_over_something_else_on_the_port(machine):
    from tainttrail.installer import setup

    kw = {**machine["kw"], "port_free": lambda p: False}
    res = setup(system="windows", **kw)
    assert not res.ok
    assert "port 9000" in "\n".join(res.lines)
    assert machine["calls"]["spawn"] == []


def test_setup_reports_a_daemon_that_never_answers(machine):
    from tainttrail.installer import setup

    kw = {**machine["kw"], "spawn": lambda argv: None}          # never comes up
    res = setup(system="windows", **kw)
    assert not res.ok and "did not answer" in "\n".join(res.lines)


def test_uninstall_reverses_setup_and_keeps_the_data(machine, monkeypatch):
    from tainttrail import hookinstall, installer

    assert installer.setup(system="windows", **machine["kw"]).ok
    stopped = []
    monkeypatch.setattr(installer.daemonctl, "stop", lambda: stopped.append(1) or (True, "stopped"))
    res = installer.uninstall(system="windows", runner=machine["kw"]["runner"])
    assert res.ok, res.lines
    hooks = _hooks(machine["settings"])
    assert not any(hookinstall.is_ours(h) for h in hooks) and GOPLUS in hooks
    startup = machine["home"] / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    assert not (startup / "tainttrail-daemon.vbs").exists()
    assert stopped == [1]
    home = machine["home"] / ".tainttrail"
    assert (home / "tainttrail.json").exists() and (home / "tainttrail.policy.yaml").exists()
    assert "kept" in "\n".join(res.lines)


def test_uninstall_only_removes_our_own_startup_file(machine, monkeypatch):
    from tainttrail import installer

    startup = machine["home"] / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    startup.mkdir(parents=True)
    (startup / "agentguard-daemon.vbs").write_text("someone else's", encoding="utf-8")
    (startup / "other.lnk").write_text("x", encoding="utf-8")
    monkeypatch.setattr(installer.daemonctl, "stop", lambda: (True, "stopped"))
    installer.uninstall(system="windows", runner=machine["kw"]["runner"])
    assert (startup / "agentguard-daemon.vbs").exists() and (startup / "other.lnk").exists()


def test_an_agent_running_uninstall_is_self_protection(db_path, monkeypatch, tmp_path_factory=None):
    from tainttrail.hooks import HookEngine
    from tainttrail.policy import from_dict

    engine = HookEngine(from_dict({"hard_enforce": ["self_protection"]}), db_path=db_path)
    engine.handle({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "D:/p",
                   "tool_name": "Bash", "tool_input": {"command": "tainttrail uninstall"},
                   "tool_use_id": "t"})
    assert "hard_enforce:self_protection" in engine.events[-1]["signals"]


def test_cli_wiring(machine, monkeypatch, capsys):
    from tainttrail import installer
    from tainttrail.cli import main

    seen = {}
    monkeypatch.setattr(installer, "setup", lambda **kw: seen.update(kw) or
                        installer.InstallerResult(True, ["done"]))
    assert main(["setup", "--enforce", "--no-start"]) == 0
    assert seen["enforce"] is True and seen["start"] is False
    monkeypatch.setattr(installer, "uninstall", lambda **kw: installer.InstallerResult(True, ["bye"]))
    assert main(["uninstall"]) == 0
