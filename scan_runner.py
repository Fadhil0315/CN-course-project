"""Process isolation gives UI/CLI scans a wall-clock deadline, including native decoding."""

from __future__ import annotations

import multiprocessing
import time

from pipeline import _base_report, _finish, analyze_image, analyze_url_input, run_demo
from shared.contracts import error_record

MAX_SCAN_SECONDS = 60.0


def _scan(kind: str, payload, options: dict) -> dict:
    if kind == "demo":
        return run_demo(payload)
    if kind in {"image", "camera"}:
        result = analyze_image(payload, **options)
        result["input"]["kind"] = kind
        return result
    if kind == "url":
        return analyze_url_input(payload, **options)
    raise ValueError("Unsupported scan input kind")


def _worker(connection, kind, payload, options):
    try:
        connection.send((True, _scan(kind, payload, options)))
    except Exception as exc:
        connection.send((False, type(exc).__name__))
    finally:
        connection.close()


def scan(kind: str, payload, *, timeout: float = MAX_SCAN_SECONDS, **options) -> dict:
    """Terminate an over-budget worker; never leave a live request running in the UI."""
    if not 0 < timeout <= 120:
        raise ValueError("Scan timeout must be between 0 and 120 seconds")
    started = time.monotonic()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(sender, kind, payload, options), daemon=True)
    report = None
    failure = "SCAN_TIMEOUT"
    try:
        process.start()
        sender.close()
        if receiver.poll(timeout):
            try:
                success, result = receiver.recv()
            except EOFError:
                success, result = False, "WorkerExited"
            if success:
                report = result
            else:
                failure = "SCAN_FAILED"
    finally:
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join(timeout=2)
            process.close()
        sender.close()
        receiver.close()
    if report is None:
        report = _base_report(kind, "live" if options.get("live") else "offline")
        report["errors"].append(
            error_record(
                failure,
                "The scan exceeded its deadline and was stopped."
                if failure == "SCAN_TIMEOUT"
                else "The isolated scan worker could not finish.",
            )
        )
        report = _finish(report, use_network=False)
    report["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return report
