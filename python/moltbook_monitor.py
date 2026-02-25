#!/usr/bin/env python3
"""
Moltbook Bridge Monitor

Checks bridge health, auto-restarts if dead, writes status to ~/.config/observer/status.json.
Designed to run from cron every 30 minutes.
"""

import json
import subprocess
import time
from pathlib import Path
from datetime import datetime

# Paths
STATUS_FILE = Path.home() / ".config" / "observer" / "status.json"
RAW_DIR = Path.home() / ".config" / "observer" / "raw"
BRIDGE_SCRIPT = Path(__file__).parent / "moltbook_bridge.py"
WORLD_BRIDGE_SCRIPT = Path(__file__).parent / "world_data_bridge.py"
BRIDGE_LOG = Path(__file__).parent.parent / "bridge.log"
WORLD_BRIDGE_LOG = Path(__file__).parent.parent / "world_bridge.log"
CONVERTER_LOG = Path(__file__).parent.parent / "converter.log"
MONITOR_LOG = Path(__file__).parent.parent / "monitor.log"
FINANCIAL_CONVERTER_LOG = Path.home() / "sovereignlabs" / "sovereign-financial-dojo" / "converter.log"
FINANCIAL_DOJO_DIR = Path.home() / ".config" / "observer" / "scenarios" / "financial_dojo"


def check_bridge_running() -> tuple[bool, int | None]:
    """Check if moltbook_bridge.py is running. Returns (running, pid)."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "moltbook_bridge.py"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            pids = result.stdout.strip().split("\n")
            # Filter out our own process and grep itself
            real_pids = [int(p) for p in pids if p.strip()]
            if real_pids:
                return True, real_pids[0]
        return False, None
    except Exception:
        return False, None


def check_raw_data_freshness() -> tuple[bool, float]:
    """Check if raw data dir has been modified in the last 2 hours."""
    if not RAW_DIR.exists():
        return False, -1

    files = list(RAW_DIR.glob("*.json"))
    if not files:
        return False, -1

    newest = max(f.stat().st_mtime for f in files)
    age_hours = (time.time() - newest) / 3600
    return age_hours < 2.0, round(age_hours, 2)


def check_converter_errors() -> tuple[bool, str]:
    """Check if converter.log has recent errors."""
    if not CONVERTER_LOG.exists():
        return True, "no log file"

    try:
        text = CONVERTER_LOG.read_text()
        lines = text.strip().split("\n")
        # Check last 50 lines for errors
        recent = lines[-50:] if len(lines) > 50 else lines
        errors = [l for l in recent if "error" in l.lower() or "traceback" in l.lower()]
        if errors:
            return False, errors[-1][:200]
        return True, "ok"
    except Exception as e:
        return False, str(e)[:200]


def check_financial_converter_errors() -> tuple[bool, str]:
    """Check if financial converter log has recent errors."""
    if not FINANCIAL_CONVERTER_LOG.exists():
        return True, "no log file"
    try:
        text = FINANCIAL_CONVERTER_LOG.read_text()
        lines = text.strip().split("\n")
        recent = lines[-50:] if len(lines) > 50 else lines
        errors = [l for l in recent if "error" in l.lower() or "traceback" in l.lower()]
        if errors:
            return False, errors[-1][:200]
        return True, "ok"
    except Exception as e:
        return False, str(e)[:200]


def check_financial_dojo_freshness() -> tuple[bool, float]:
    """Check if financial_dojo output has been updated within 4 hours."""
    if not FINANCIAL_DOJO_DIR.exists():
        return False, -1
    files = list(FINANCIAL_DOJO_DIR.glob("*.json"))
    files = [f for f in files if not f.name.startswith("_")]  # skip _conversion_stats.json
    if not files:
        return False, -1
    newest = max(f.stat().st_mtime for f in files)
    age_hours = (time.time() - newest) / 3600
    return age_hours < 4.0, round(age_hours, 2)


def check_world_bridge_running() -> tuple[bool, int | None]:
    """Check if world_data_bridge.py is running. Returns (running, pid)."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "world_data_bridge.py"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            pids = result.stdout.strip().split("\n")
            real_pids = [int(p) for p in pids if p.strip()]
            if real_pids:
                return True, real_pids[0]
        return False, None
    except Exception:
        return False, None


def restart_bridge():
    """Restart the moltbook bridge process in the background."""
    try:
        subprocess.Popen(
            ["python3", str(BRIDGE_SCRIPT)],
            cwd=str(BRIDGE_SCRIPT.parent.parent),
            stdout=open(str(BRIDGE_LOG), "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True
        )
        return True
    except Exception as e:
        return False


def restart_world_bridge():
    """Restart the world data bridge process in the background."""
    try:
        subprocess.Popen(
            ["python3", str(WORLD_BRIDGE_SCRIPT)],
            cwd=str(WORLD_BRIDGE_SCRIPT.parent.parent),
            stdout=open(str(WORLD_BRIDGE_LOG), "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True
        )
        return True
    except Exception as e:
        return False


def run_monitor():
    """Run all health checks and write status."""
    now = datetime.now(tz=__import__('datetime').timezone.utc).isoformat()

    bridge_running, bridge_pid = check_bridge_running()
    world_bridge_running, world_bridge_pid = check_world_bridge_running()
    data_fresh, data_age_hours = check_raw_data_freshness()
    converter_ok, converter_msg = check_converter_errors()
    fin_converter_ok, fin_converter_msg = check_financial_converter_errors()
    fin_dojo_fresh, fin_dojo_age_hours = check_financial_dojo_freshness()

    restarted = False
    if not bridge_running:
        restarted = restart_bridge()

    world_restarted = False
    if not world_bridge_running:
        world_restarted = restart_world_bridge()

    status = {
        "timestamp": now,
        "bridge_running": bridge_running,
        "bridge_pid": bridge_pid,
        "world_bridge_running": world_bridge_running,
        "world_bridge_pid": world_bridge_pid,
        "data_fresh": data_fresh,
        "data_age_hours": data_age_hours,
        "converter_ok": converter_ok,
        "converter_msg": converter_msg,
        "financial_converter_ok": fin_converter_ok,
        "financial_converter_msg": fin_converter_msg,
        "financial_dojo_fresh": fin_dojo_fresh,
        "financial_dojo_age_hours": fin_dojo_age_hours,
        "auto_restarted": restarted,
        "world_auto_restarted": world_restarted,
    }

    # Determine overall health
    all_ok = bridge_running and world_bridge_running and data_fresh and converter_ok and fin_converter_ok and fin_dojo_fresh
    if all_ok:
        status["health"] = "healthy"
    elif (bridge_running or world_bridge_running) and not data_fresh:
        status["health"] = "stale"
    elif not bridge_running and not world_bridge_running:
        status["health"] = "restarted" if (restarted or world_restarted) else "dead"
    else:
        status["health"] = "degraded"

    # Write status.json
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(json.dumps(status, indent=2))

    # Append one-liner to monitor.log
    one_liner = f"[{now}] health={status['health']} moltbook={'up' if bridge_running else 'down'} world={'up' if world_bridge_running else 'down'} data_age={data_age_hours}h converter={converter_msg[:40]} fin_converter={fin_converter_msg[:30]} fin_dojo_age={fin_dojo_age_hours}h"
    if restarted:
        one_liner += " MOLTBOOK_RESTARTED"
    if world_restarted:
        one_liner += " WORLD_RESTARTED"
    with open(str(MONITOR_LOG), "a") as f:
        f.write(one_liner + "\n")

    print(one_liner)
    return status


if __name__ == "__main__":
    run_monitor()
