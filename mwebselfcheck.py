#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2>=5.4.6,<6.0.0", "pyserial>=3.5.0,<4.0.0"]
# ///
import argparse
import logging
import time

# Silence jadepy BEFORE importing it: the module prints a BLE/aioitertools
# warning at import time, and the device-log forwarder / "Unhandled message
# received" emitter both log at ERROR — CRITICAL hides all of them.
logging.getLogger("jadepy.jade").setLevel(logging.INFO)
logging.getLogger("jadepy.jade-device").setLevel(logging.INFO)

from jadepy.jade import JadeAPI

parser = argparse.ArgumentParser(description="Run Jade debug_selfcheck_mweb.")
parser.add_argument(
    "-p",
    "--port",
    default="/dev/cu.usbmodem1234561",
    help="Serial device (default: %(default)s)",
)
args = parser.parse_args()

def _format_result(result):
    """Pretty-print a debug_selfcheck_mweb reply."""
    # CBOR keys come back as bytes when the firmware serialised them as
    # byte-strings; jadepy's decoder leaves those as-is. Normalise.
    def _k(d, key):
        if key in d:
            return d[key]
        b = key.encode()
        return d.get(b)

    results = _k(result, "results") or []
    elapsed = _k(result, "elapsed_ms")
    passed = sum(1 for r in results if _k(r, "passed"))
    failed = len(results) - passed

    name_width = max((len(_k(r, "name") or "") for r in results), default=0)
    for r in results:
        name = _k(r, "name") or "?"
        ok = _k(r, "passed")
        ms = _k(r, "elapsed_ms")
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {name:<{name_width}}  {ms:>5} ms")

    summary = f"{passed}/{len(results)} passed"
    if failed:
        summary += f", {failed} FAILED"
    print(f"\nmweb selfcheck: {summary}  ({elapsed} ms total)")
    return failed == 0


with JadeAPI.create_serial(args.port) as jade:
    ser = jade.jade.impl.ser

    time.sleep(1)
    ser.reset_input_buffer()
    orig_timeout = ser.timeout
    ser.timeout = 0.5
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if not ser.read(4096):
                break  # no more data within 500 ms
    finally:
        ser.timeout = orig_timeout

    reply = jade.run_remote_selfcheck_mweb()
    ok = _format_result(reply)
    raise SystemExit(0 if ok else 1)
