"""Pinned re-run executor — the killer feature.

With --rerun (explicit buyer consent), the buyer RE-EXECUTES the pinned
evaluation command against the pinned artifacts/data in the claim directory
and compares the reproduced metric to the claimed value. "The claim is
provable, re-derived by a neutral party" is literally: the command ran, the
number came out.

Safety model:
  - the command is exactly the pinned string in the claim (hashed into the
    signature) — the buyer can read it before running; nothing hidden
  - NEVER runs through a shell: the pinned string is split with shlex into
    an argv list and executed directly. Shell metacharacters (`;`, `|`,
    `&&`, backticks, `$()`, redirections) have no special meaning — a
    malicious command string cannot chain extra commands.
  - runs with cwd = claim base_dir, a timeout, and with network-related
    env vars stripped by default (--no-env-scrub to disable)
  - stdout must end with one JSON object; the metric field is compared to
    the claimed value within tolerance. Non-finite values or tolerances
    always FAIL.
  - callers must only invoke this after L1+L2+L3 pass and after explicit
    buyer consent (--rerun); verify_claim enforces both.
"""
import json
import math
import os
import shlex
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
    """Run the pinned command WITHOUT a shell; return {ok, metrics, error, duration_s}."""
    try:
        argv = shlex.split(command)
    except ValueError as ex:
        return {"ok": False, "metrics": None,
                "error": f"unparseable command (no shell is used): {ex}",
                "duration_s": None}
    if not argv:
        return {"ok": False, "metrics": None, "error": "empty command",
                "duration_s": None}
    env = scrub_env(dict(os.environ)) if env_scrub else dict(os.environ)
    try:
        proc = subprocess.run(argv, shell=False, cwd=base_dir,
                              capture_output=True, text=True, timeout=timeout_s,
                              env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "metrics": None, "error": f"timeout {timeout_s}s",
                "duration_s": timeout_s}
    except OSError as ex:
        return {"ok": False, "metrics": None,
                "error": f"could not execute {argv[0]!r}: {ex}",
                "duration_s": None}
    if log_path:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"$ {' '.join(argv)}\n\n--- stdout ---\n{proc.stdout}\n"
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
    if metrics is None:
        return {"ok": False, "metrics": None,
                "error": "no JSON object on stdout", "duration_s": None}
    return {"ok": True, "metrics": metrics, "error": None, "duration_s": None}


def compare_metric(claimed, reproduced, tolerance: float = 0.0) -> tuple:
    """-> (ok, detail). Non-finite inputs or tolerance always FAIL."""
    try:
        vals = (float(claimed), float(reproduced), float(tolerance))
        finite = all(math.isfinite(v) for v in vals)
    except (TypeError, ValueError):
        finite = False
    if not finite:
        return False, (f"non-finite value in comparison "
                       f"(claimed {claimed}, rerun {reproduced}, tol {tolerance})")
    ok = abs(float(claimed) - float(reproduced)) <= float(tolerance)
    return ok, (f"claimed {claimed} vs rerun {reproduced} "
                f"(tol {tolerance})")
