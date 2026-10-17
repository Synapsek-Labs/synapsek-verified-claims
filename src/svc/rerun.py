"""Pinned re-run executor — the killer feature.

With --rerun, the buyer RE-EXECUTES the pinned evaluation command against
the pinned artifacts/data in the claim directory and compares the
reproduced metric to the claimed value. "The claim is provable, re-derived
by a neutral party" is literally: the command ran, the number came out.

Safety model:
  - the command is exactly the pinned string in the claim (hashed into the
    signature) — the buyer can read it before running; nothing hidden
  - runs with cwd = claim base_dir, a timeout, and with network-related
    env vars stripped by default (--no-env-scrub to disable)
  - stdout must end with one JSON object; the metric field is compared
    to the claimed value within tolerance.
"""

import json
import os
import subprocess

STRIP_ENV_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                  "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY")


def scrub_env(base: dict) -> dict:
    env = {k: v for k, v in base.items()}
    for k in STRIP_ENV_VARS:
        env.pop(k, None)
    env["PYTHONHASHSEED"] = "0"
    return env


def run_pinned(command: str, base_dir: str, timeout_s: int = 3600,
               env_scrub: bool = True, log_path: str = None) -> dict:
    """Run the pinned command; return {ok, metrics, error, duration_s}."""
    env = scrub_env(dict(os.environ)) if env_scrub else dict(os.environ)
    try:
        proc = subprocess.run(command, shell=True, cwd=base_dir,
                              capture_output=True, text=True, timeout=timeout_s,
                              env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "metrics": None, "error": f"timeout {timeout_s}s",
                "duration_s": timeout_s}
    if log_path:
        with open(log_path, "w") as f:
            f.write(f"$ {command}\n\n--- stdout ---\n{proc.stdout}\n"
                    f"--- stderr ---\n{proc.stderr}\n")
    if proc.returncode != 0:
        return {"ok": False, "metrics": None,
                "error": f"exit {proc.returncode}: {proc.stderr[-400:]}",
                "duration_s": None}
    # metrics = last non-empty stdout line that parses as a JSON object
    metrics = None
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            metrics = obj
            break
        break
    if metrics is None:
        return {"ok": False, "metrics": None,
                "error": "no JSON object on stdout", "duration_s": None}
    return {"ok": True, "metrics": metrics, "error": None, "duration_s": None}


def compare_metric(claimed: float, reproduced: float,
                   tolerance: float = 0.0) -> tuple:
    """-> (ok, detail)"""
    ok = abs(float(claimed) - float(reproduced)) <= tolerance
    return ok, (f"claimed {claimed} vs rerun {reproduced} "
                f"(tol {tolerance})")
