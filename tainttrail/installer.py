"""`tainttrail setup` / `tainttrail uninstall`: the whole install in one command.

`setup` does, in order, and each step is idempotent:

  1. stops if a pre-rename AgentGuard install hasn't been migrated yet (running
     setup first would create a fresh home that `migrate` then refuses to fill)
  2. config: the existing one, or defaults (observe mode unless --enforce)
  3. policy: kept if the config already names one; otherwise the starter policy is
     written into the TaintTrail home - not the current folder - so it doesn't
     depend on where setup was run
  4. Claude Code hooks (user settings), recognising only our own exact entries
  5. the background daemon, without Administrator rights:
       Windows  hidden launcher started with wscript; auto-start by a copy of the
                launcher in the user's Startup folder (no Task Scheduler)
       Linux    systemd user unit, `systemctl --user enable --now`
       macOS    LaunchAgent, `launchctl load -w`
  6. waits for the daemon to answer, then runs `doctor`

`uninstall` removes our hook entries, stops the daemon and removes the auto-start
entry it created. It keeps the config, policy and audit log, and says where they are.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from tainttrail import config as cfg
from tainttrail import daemonctl

STARTUP_FILENAME = "tainttrail-daemon.vbs"


@dataclass
class InstallerResult:
    ok: bool = False
    lines: list[str] = field(default_factory=list)


def windows_startup_dir() -> Path:
    appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def _spawn_detached(argv: list[str]) -> None:
    kwargs: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                              "stderr": subprocess.DEVNULL, "close_fds": True}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x00000008 | 0x00000200   # DETACHED | NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(argv, **kwargs)                        # noqa: S603


def _port_free(port: int) -> bool:
    from tainttrail.doctor import _port_is_free

    return _port_is_free(port)


def _legacy_install() -> Path | None:
    """The pre-rename config file, looked up by exact name only."""
    old = Path(os.environ.get(cfg.LEGACY_HOME_ENV) or Path.home() / cfg.LEGACY_HOME_DIRNAME)
    marker = old / cfg.LEGACY_CONFIG_FILENAME
    return marker if marker.is_file() else None


def setup(*, enforce: bool = False, system: str | None = None, start: bool = True,
          autostart: bool = True, port: int | None = None,
          runner: Callable[..., Any] = subprocess.run,
          spawn: Callable[[list[str]], None] = _spawn_detached,
          probe: Callable[..., dict | None] = daemonctl.probe,
          port_free: Callable[[int], bool] = _port_free,
          sleep: Callable[[float], None] = time.sleep,
          wait_seconds: float = 20.0) -> InstallerResult:
    from tainttrail import __version__, hookinstall
    from tainttrail.onboarding import install_daemon, write_starter_policy

    res = InstallerResult()
    say = res.lines.append
    system = (system or platform.system()).lower()
    home = cfg.tainttrail_home()

    legacy = _legacy_install()
    if legacy is not None and not cfg.exists():
        say(f"Found a pre-rename AgentGuard install ({legacy}).")
        say("Copy its state over first, then run setup again:")
        say("  tainttrail migrate --dry-run")
        say("  tainttrail migrate")
        say("Nothing was changed.")
        return res

    # --- config + policy ------------------------------------------------------
    conf = cfg.load() if cfg.exists() else cfg.Config()
    if enforce:
        conf.mode = cfg.MODE_ENFORCE
    if port:
        conf.port = port
    policy = Path(conf.policy_file) if conf.policy_file else None
    if policy is None or not policy.is_file():
        home.mkdir(parents=True, exist_ok=True)
        written = write_starter_policy(home, enforcement=conf.enforcement)
        policy = home / "tainttrail.policy.yaml"
        say(f"  policy   {policy}" + ("  (written)" if written else "  (kept)"))
    else:
        say(f"  policy   {policy}  (kept)")
    conf.policy_file = str(policy.resolve())
    say(f"  config   {cfg.save(conf)}  (mode: {conf.mode})")

    # --- hooks --------------------------------------------------------------------
    settings = hookinstall.settings_path(hookinstall.SCOPE_USER)
    hooked = hookinstall.install(settings, kind=hookinstall.KIND_HTTP, port=conf.port)
    say(f"  hooks    {settings}  ({'installed' if hooked.changed else 'already installed'};"
        f" other tools' hooks untouched)")

    if not start:
        say("")
        say("Daemon not started (--no-start). Start it with `tainttrail proxy`.")
        res.ok = True
        return res

    # --- daemon -------------------------------------------------------------------
    running = probe(conf.port)
    if running:
        if running.get("version") != __version__:
            say(f"  daemon   a TaintTrail {running.get('version', '?')} daemon is already "
                f"running on port {conf.port}; stop it (`tainttrail daemon stop`) and run "
                f"setup again to start {__version__}")
            return res
        say(f"  daemon   already running on port {conf.port}")
    else:
        if not port_free(conf.port):
            say(f"  daemon   port {conf.port} is in use by something that isn't TaintTrail "
                f"(an old AgentGuard daemon? stop it with `agentguard daemon stop`). "
                f"Or pick another port: tainttrail setup --port 9100")
            return res
        plan = install_daemon(conf, system=system, activate=False)
        if system == "windows":
            vbs = next((p for p in (plan.extra_files or {}) if p.suffix == ".vbs"), None)
            if vbs is None:
                say("  daemon   launcher missing - run `tainttrail doctor`")
                return res
            daemonctl.clear_stop_flag(home)
            spawn(["wscript.exe", str(vbs)])
            if autostart:
                startup = windows_startup_dir()
                startup.mkdir(parents=True, exist_ok=True)
                shutil.copy2(vbs, startup / STARTUP_FILENAME)
                say(f"  start    at login via {startup / STARTUP_FILENAME}")
        elif system == "linux":
            if shutil.which("systemctl") or runner is not subprocess.run:
                runner(["systemctl", "--user", "daemon-reload"], check=False)
                runner(["systemctl", "--user", "enable" if autostart else "start",
                        *(["--now"] if autostart else []), "tainttrail"], check=False)
                say(f"  start    systemd user unit {plan.path}")
            else:
                from tainttrail.onboarding import _console_parts

                spawn([*_console_parts(), "proxy", "--port", str(conf.port)])
                say("  start    no systemd here: started `tainttrail proxy` in the background "
                    "(it won't come back after a reboot)")
        elif system == "darwin":
            runner(["launchctl", "load", "-w", str(plan.path)], check=False)
            say(f"  start    LaunchAgent {plan.path}")
        else:
            say(f"  daemon   unsupported platform {system!r}: run `tainttrail proxy` yourself")
            return res
        waited = 0.0
        while not probe(conf.port) and waited < wait_seconds:
            sleep(0.5)
            waited += 0.5
        if not probe(conf.port):
            say(f"  daemon   did not answer on port {conf.port} within {int(wait_seconds)}s - "
                f"see {home / 'daemon.log'} and `tainttrail doctor`")
            return res
        say(f"  daemon   running on http://127.0.0.1:{conf.port}")

    say("")
    say("Claude Code is now protected by TaintTrail "
        + ("(ENFORCING: risky calls are blocked or asked)." if conf.enforcement else
           "(observe mode: it logs, and blocks only the hard-enforced list)."))
    say("  tainttrail status          what's running")
    say("  tainttrail report          what it flagged")
    say("  tainttrail demo            see the headline attack get stopped")
    say("  tainttrail uninstall       undo all of this (keeps your audit log)")
    res.ok = True
    return res


def uninstall(*, system: str | None = None,
              runner: Callable[..., Any] = subprocess.run) -> InstallerResult:
    from tainttrail import hookinstall
    from tainttrail.onboarding import LAUNCHD_LABEL, SERVICE_NAME

    res = InstallerResult()
    say = res.lines.append
    system = (system or platform.system()).lower()
    settings = hookinstall.settings_path(hookinstall.SCOPE_USER)
    try:
        removed = hookinstall.uninstall(settings)
        say(f"  hooks    {removed.message} ({settings})")
    except hookinstall.HookInstallError as exc:
        say(f"  hooks    {exc}")
    ok, message = daemonctl.stop()
    say(f"  daemon   {message}")
    if system == "windows":
        entry = windows_startup_dir() / STARTUP_FILENAME
        if entry.is_file():
            entry.unlink()
            say(f"  start    removed {entry}")
    elif system == "linux":
        runner(["systemctl", "--user", "disable", "--now", SERVICE_NAME], check=False)
        say("  start    systemd user unit disabled")
    elif system == "darwin":
        plist = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        if plist.is_file():
            runner(["launchctl", "unload", "-w", str(plist)], check=False)
            say("  start    LaunchAgent unloaded")
    say("")
    say(f"kept: your config, policy and audit log in {cfg.tainttrail_home()} - delete that "
        f"folder yourself if you no longer want them")
    res.ok = True
    return res
