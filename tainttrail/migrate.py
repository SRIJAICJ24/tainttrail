"""`tainttrail migrate`: copy state from the pre-rename ~/.agentguard into ~/.tainttrail.

Until 0.5.0 this project was called AgentGuard and kept its state in ~/.agentguard.
Other tools use that folder too - GoPlus Security's AgentGuard writes audit.jsonl
and more there - so this module:

  * looks up only the files this project created, by exact name; it never lists the
    folder, so it cannot pick up, read or touch another tool's files
  * copies, never moves or deletes; the old folder is left byte-for-byte as it was
  * opens the old database read-only and copies it with SQLite's backup API
  * regenerates the Windows launchers for the new name instead of copying the old
    ones, which run `agentguard ... proxy` with AGENTGUARD_HOME set
  * copies the policy file the config points at to `tainttrail.policy.yaml` beside
    it when it still has the old name
  * verifies afterwards: config loads, audit chain intact, every table has the same
    row count, the quarantine ledger has the same items, the policy hash is the same
  * refuses to overwrite a home that already has TaintTrail state
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from tainttrail import config as cfg

LEGACY_POLICY_FILENAME = "agentguard.policy.yaml"
LEGACY_LAUNCHER = "agentguard-daemon.cmd"
#: Files of ours carried over unchanged (the pid and stop flag are run-time only).
_COPY_AS_IS = ("daemon.log",)


@dataclass
class MigrateResult:
    ok: bool = False
    lines: list[str] = field(default_factory=list)

    def say(self, line: str) -> None:
        self.lines.append(line)


def default_source() -> Path:
    return Path(os.environ.get(cfg.LEGACY_HOME_ENV) or Path.home() / cfg.LEGACY_HOME_DIRNAME)


def default_destination() -> Path:
    # Never the deprecated alias: that would point back at the old folder.
    return Path(os.environ.get(cfg.HOME_ENV) or Path.home() / ".tainttrail")


def _tables(db: Path, *, read_only: bool) -> dict[str, int]:
    uri = db.resolve().as_uri() + ("?mode=ro" if read_only else "")
    conn = sqlite3.connect(uri, uri=True)
    try:
        names = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        return {n: conn.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0] for n in names}
    finally:
        conn.close()


def _copy_db(src: Path, dst: Path) -> None:
    source = sqlite3.connect(src.resolve().as_uri() + "?mode=ro", uri=True)
    target = sqlite3.connect(str(dst))
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def migrate(src: Path | str | None = None, dst: Path | str | None = None, *,
            dry_run: bool = False, system: str | None = None) -> MigrateResult:
    from tainttrail import audit
    from tainttrail.policy import load as load_policy
    from tainttrail.quarantine import QuarantinedMemoryLedger
    from tainttrail.versions import policy_version

    src = Path(src) if src else default_source()
    dst = Path(dst) if dst else default_destination()
    res = MigrateResult()
    res.say(f"from {src}")
    res.say(f"to   {dst}")

    if src.resolve() == dst.resolve():
        res.say("source and destination are the same folder - nothing to do")
        return res
    old_cfg_file = src / cfg.LEGACY_CONFIG_FILENAME
    old_db = src / cfg.LEGACY_DB_FILENAME
    if not old_cfg_file.is_file() and not old_db.is_file():
        res.say(f"no {cfg.LEGACY_CONFIG_FILENAME} or {cfg.LEGACY_DB_FILENAME} in {src} - "
                f"nothing from the pre-rename install to migrate")
        return res
    new_cfg_file = dst / cfg.CONFIG_FILENAME
    new_db = dst / "tainttrail.db"
    if new_cfg_file.exists() or new_db.exists():
        res.say(f"{dst} already has TaintTrail state ({new_cfg_file.name} or {new_db.name}) - "
                f"refusing to overwrite it")
        return res

    # --- plan --------------------------------------------------------------
    conf = cfg.load(old_cfg_file) if old_cfg_file.is_file() else cfg.Config()
    old_policy = Path(conf.policy_file) if conf.policy_file else None
    new_policy = old_policy
    copy_policy = False
    if old_policy is not None and old_policy.is_file() and old_policy.name == LEGACY_POLICY_FILENAME:
        candidate = old_policy.with_name("tainttrail.policy.yaml")
        if not candidate.exists():
            new_policy, copy_policy = candidate, True
        elif candidate.read_bytes() == old_policy.read_bytes():
            new_policy = candidate
        else:
            res.say(f"note: {candidate} exists with different content - keeping the "
                    f"policy at {old_policy}")
    windows = (system or __import__("platform").system()).lower() == "windows"
    launchers = windows and (src / LEGACY_LAUNCHER).is_file()

    res.say("")
    res.say("will copy:")
    if old_cfg_file.is_file():
        res.say(f"  {cfg.LEGACY_CONFIG_FILENAME:<24} -> {cfg.CONFIG_FILENAME}"
                + (f" (policy_file -> {new_policy})" if copy_policy else ""))
    if old_db.is_file():
        res.say(f"  {cfg.LEGACY_DB_FILENAME:<24} -> tainttrail.db (audit log, quarantine "
                f"ledger, review queue, labels)")
    for name in _COPY_AS_IS:
        if (src / name).is_file():
            res.say(f"  {name:<24} -> {name}")
    if copy_policy:
        res.say(f"  {old_policy} -> {new_policy}")
    if launchers:
        res.say("  launchers: regenerated as tainttrail-daemon.cmd / .vbs (the old ones run "
                "the old command)")
    res.say("will not touch: anything else in the old folder, which is left exactly as it is")
    if dry_run:
        res.say("")
        res.say("dry run - nothing written")
        res.ok = True
        return res

    # --- copy --------------------------------------------------------------
    dst.mkdir(parents=True, exist_ok=True)
    before = _tables(old_db, read_only=True) if old_db.is_file() else {}
    old_chain = audit.verify_chain(str(old_db))[0] if old_db.is_file() else True
    if old_db.is_file():
        _copy_db(old_db, new_db)
    for name in _COPY_AS_IS:
        if (src / name).is_file():
            shutil.copy2(src / name, dst / name)
    if copy_policy and old_policy is not None and new_policy is not None:
        shutil.copy2(old_policy, new_policy)
    conf.policy_file = str(new_policy) if new_policy else None
    cfg.save(conf, new_cfg_file)
    if launchers:
        from tainttrail.onboarding import install_daemon

        saved = os.environ.get(cfg.HOME_ENV)
        os.environ[cfg.HOME_ENV] = str(dst)
        try:
            install_daemon(conf, system="windows", activate=False)
        finally:
            if saved is None:
                os.environ.pop(cfg.HOME_ENV, None)
            else:
                os.environ[cfg.HOME_ENV] = saved

    # --- verify ------------------------------------------------------------
    problems: list[str] = []
    try:
        cfg.load(new_cfg_file)
    except cfg.ConfigError as exc:
        problems.append(f"config: {exc}")
    if old_db.is_file():
        after = _tables(new_db, read_only=True)
        for table, count in before.items():
            if after.get(table) != count:
                problems.append(f"table {table}: {count} rows before, {after.get(table)} after")
        intact, broken = audit.verify_chain(str(new_db))
        if old_chain and not intact:
            problems.append(f"audit chain broken at row {broken} after the copy")
        ledger_old = len(QuarantinedMemoryLedger(str(old_db)).list(status=None, include_expired=True)) \
            if "quarantine" in before else 0
        ledger_new = len(QuarantinedMemoryLedger(str(new_db)).list(status=None, include_expired=True)) \
            if "quarantine" in after else 0
        if ledger_old != ledger_new:
            problems.append(f"quarantine ledger: {ledger_old} items before, {ledger_new} after")
    if copy_policy and old_policy is not None and new_policy is not None:
        if policy_version(load_policy(old_policy)) != policy_version(load_policy(new_policy)):
            problems.append("policy hash changed in the copy")

    res.say("")
    if problems:
        res.say("verification FAILED:")
        res.lines.extend(f"  {p}" for p in problems)
        res.say(f"the old folder {src} was not changed; inspect {dst} before using it")
        return res
    if old_db.is_file():
        res.say(f"verified: audit chain {'intact' if old_chain else 'was already broken before'}"
                f" ({before.get('audit', 0)} rows), {sum(before.values())} rows in "
                f"{len(before)} tables match, quarantine ledger {ledger_new} item(s) match")
    else:
        res.say("verified: config loads (there was no database to copy)")
    if conf.policy_file:
        res.say(f"policy: {conf.policy_file}")
    gateway_note = conf.policy_file and Path(conf.policy_file).is_file() and \
        "agentguard" in str(load_policy(conf.policy_file).hooks.gateway_servers)
    if gateway_note:
        res.say("note: your policy lists 'agentguard' under hooks.gateway_servers. If you "
                "never routed an MCP server named 'agentguard' through this gateway, remove it - "
                "another tool's MCP server with that name would skip the hook checks.")
    res.say("")
    res.say("next:")
    res.say("  tainttrail install-hooks       (replaces the old hook entries, keeps everyone else's)")
    if launchers:
        res.say(f"  wscript \"{dst / 'tainttrail-daemon.vbs'}\"")
        res.say("  Startup folder: delete agentguard-daemon.vbs there and copy "
                "tainttrail-daemon.vbs in its place, or the old daemon starts at login")
    else:
        res.say("  tainttrail proxy   (or `tainttrail onboard --install-daemon`)")
    res.say("  tainttrail doctor && tainttrail status")
    res.say(f"the old folder {src} is unchanged; delete our old files there yourself once "
            f"everything works")
    res.ok = True
    return res
