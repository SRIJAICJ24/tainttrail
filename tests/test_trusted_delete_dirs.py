"""Trusted delete folders, and deletes inside nested `bash -c "..."` scripts.

Real case (2026-10-16, review items #8 and #9): Claude ran a game's online test
through WSL - `wsl.exe -d Ubuntu -e bash -c "cd ~/bbtest && rm -rf logs && ..."`.
Enforce mode asked for permission each time. Two gaps: there was no way to say
"deletes inside ~/bbtest are fine", and the analysis never looked inside the
quoted `bash -c` script, so it couldn't tell where the delete landed.
"""

from __future__ import annotations

import pytest

SP = "C:/Users/me/AppData/Local/Temp/claude/D--GAME/9eb6425e/scratchpad"
# review item #9, anonymized and shortened
REAL_9 = (f'SP="{SP}"; rm -f "$SP/online/w"*.log; (wsl.exe -d Ubuntu -e bash -c '
          f'"cd ~/bbtest && rm -rf logs && timeout 220 python3 bb_lobby.py --bin '
          f'\\$HOME/bbtest/Server.x86_64 --port 25680 --log-dir \\$HOME/bbtest/logs '
          f"--extra '--low-spec --unlock-all'\" > \"$SP/online/wsl_lobby.log\" 2>&1 &); sleep 5")


def _engine(db_path, trusted=None):
    from tainttrail.hooks import HookEngine
    from tainttrail.policy import from_dict

    hooks = {} if trusted is None else {"trusted_delete_dirs": trusted}
    return HookEngine(from_dict({"hooks": hooks}), db_path=db_path)


def run(db_path, command, trusted=None):
    engine = _engine(db_path, trusted)
    engine.handle({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "D:/GAME",
                   "tool_name": "Bash", "tool_input": {"command": command},
                   "tool_use_id": "t"})
    return engine.events[-1]


TRUSTED_OK = [
    REAL_9,
    'wsl.exe -d Ubuntu -e bash -c "cd ~/bbtest && rm -rf logs"',
    "rm -rf ~/bbtest/logs",
    "rm -rf $HOME/bbtest/build ~/bbtest/logs/*",
    "cd ~/bbtest && rm -rf out",
    "bash -c 'cd ~/bbtest/run && rm -rf tmp'",
]


@pytest.mark.parametrize("command", TRUSTED_OK)
def test_deletes_inside_a_trusted_folder_are_logged_not_flagged(db_path, command):
    ev = run(db_path, command, trusted=["~/bbtest"])
    assert "hook:destructive_command" not in ev["signals"], ev
    assert "hook:delete_in_trusted_dir" in ev["signals"], ev
    assert ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("command", TRUSTED_OK)
def test_without_the_setting_they_are_still_flagged(db_path, command):
    ev = run(db_path, command)
    assert "hook:destructive_command" in ev["signals"], ev


STILL_FLAGGED = [
    "rm -rf ~/bbtest",                                  # the folder itself
    "rm -rf ~/bbtest/../projects",                      # escapes it
    "cd ~/bbtest && rm -rf ../projects",
    "rm -rf ~/bbtest2/x",                               # prefix look-alike
    'wsl.exe -d Ubuntu -e bash -c "rm -rf ~/projects"',
    'bash -c "cd ~/bbtest && cd .. && rm -rf x"',
    'bash -c "cd ~/bbtest && rm -rf $UNKNOWN/x"',
    "rm -rf ~/bbtest/logs ~/Documents",                 # one trusted, one not
    'wsl.exe -e bash -c "cd ~/bbtest && rm -rf logs" && rm -rf ~/projects',
]


@pytest.mark.parametrize("command", STILL_FLAGGED)
def test_everything_else_is_still_flagged(db_path, command):
    ev = run(db_path, command, trusted=["~/bbtest"])
    assert "hook:destructive_command" in ev["signals"], ev
    assert ev["verdict"] in ("REVIEW", "BLOCK"), ev


@pytest.mark.parametrize("command", [
    "bash -c 'rm -rf /tmp/agx-build'",
    f'wsl.exe -e bash -c "rm -rf /tmp/agx-cache"',
])
def test_nested_deletes_in_temp_are_recognised_too(db_path, command):
    ev = run(db_path, command)
    assert "hook:delete_in_temp" in ev["signals"] and ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("bad", ["~", "~/", "/", "C:/", "C:\\", "$HOME", "/home", "D:"])
def test_trusting_a_home_or_root_is_refused(bad):
    from tainttrail.policy import from_dict

    with pytest.raises(ValueError):
        from_dict({"hooks": {"trusted_delete_dirs": [bad]}})


# =========================================================================
# From a month in enforce mode (2026-10-23 .. 11-22): 13 of 16 approved prompts
# were deletes of generated output inside the project (Screenshots/..., Sandbox,
# scan output), and one was Remove-Item inside a PowerShell `{ }` block on a temp
# folder that should already have been exempt (#36).
# =========================================================================
WS = "D:/GAME/GameUnity"


def run_in(db_path, command, cwd=WS, trusted=None, tool="Bash"):
    engine = _engine(db_path, trusted)
    engine.handle({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": cwd,
                   "tool_name": tool, "tool_input": {"command": command}, "tool_use_id": "t"})
    return engine.events[-1]


@pytest.mark.parametrize("command", [
    "rm -rf Screenshots/santa",
    "rm -rf Screenshots/santa/*.png; ub_test x",
    "ub_compile && rm -rf Screenshots/sweep && ub_test y",
    "rm -rf ./Screenshots/santa/super",
])
def test_project_relative_trusted_folders(db_path, command):
    ev = run_in(db_path, command, trusted=["Screenshots"])
    assert "hook:delete_in_trusted_dir" in ev["signals"] and ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("command", [
    "rm -rf Screenshots",                        # the folder itself
    "rm -rf ../Screenshots/x",                   # another project's
    "cd /d/other && rm -rf Screenshots/x",       # not the session's project any more
    "rm -rf Screenshots/x Assets",               # one trusted, one not
    "rm -rf ScreenshotsOld/x",                   # look-alike prefix
])
def test_project_relative_trust_is_narrow(db_path, command):
    ev = run_in(db_path, command, trusted=["Screenshots"])
    assert "hook:destructive_command" in ev["signals"], ev


def test_project_relative_entry_needs_a_project(db_path):
    ev = run_in(db_path, "rm -rf Screenshots/x", cwd=None, trusted=["Screenshots"])
    assert "hook:destructive_command" in ev["signals"], ev


@pytest.mark.parametrize("bad", [".", "./", "..", "../x", "a/../.."])
def test_relative_entries_that_are_too_broad_are_refused(bad):
    from tainttrail.policy import from_dict

    with pytest.raises(ValueError):
        from_dict({"hooks": {"trusted_delete_dirs": [bad]}})


REAL_36 = (r'$t = "C:\Users\me\AppData\Local\Temp\claude\315c\b63c\scratchpad\ziptest"' "\n"
           r'if (Test-Path $t) { Remove-Item $t -Recurse -Force }' "\n"
           r'Expand-Archive -Path out.zip -DestinationPath $t')


def test_powershell_block_on_a_temp_folder_is_recognised(db_path):
    ev = run_in(db_path, REAL_36, tool="PowerShell")
    assert "hook:delete_in_temp" in ev["signals"] and ev["verdict"] == "ALLOW", ev


@pytest.mark.parametrize("command", [
    r'if (Test-Path $t) { Remove-Item C:\Users\me\Documents -Recurse -Force }',
    r'$t = "C:\Users\me\AppData\Local\Temp\x"; if ($a) { Remove-Item $t -Recurse; Remove-Item C:\Work -Recurse }',
    'foreach ($d in $dirs) { Remove-Item $d -Recurse -Force }',
])
def test_powershell_blocks_elsewhere_stay_flagged(db_path, command):
    ev = run_in(db_path, command, tool="PowerShell")
    assert "hook:destructive_command" in ev["signals"], ev


def test_every_delete_on_a_greedily_matched_line_is_checked(db_path):
    """Regression: `Remove-Item ... -Recurse` matches greedily to the end of the line,
    so only the delete where the match started was checked. A temp delete followed
    by a real one on the same line was let through."""
    command = (r"Remove-Item $env:TEMP\ag-x -Recurse -Force; "
               r"Remove-Item C:\Users\me\Work -Recurse -Force")
    ev = run_in(db_path, command, tool="PowerShell")
    assert "hook:destructive_command" in ev["signals"], ev
