#!/usr/bin/env python3
"""Verify per-secret IP table-full handling for issue #71.

The compose rig builds the proxy with SECRET_MAX_TRACKED_IPS=4 and a secret
with max_ips=10 (loose enough that ip_over_limit admits all six handshakers,
yet the precise table only fits four — the 5th and 6th overflow into the
throttled-warning branch). This verifier asserts:

* The cumulative `teleproxy_secret_unique_ips` counter (Bloom-backed)
  reflects all six distinct source IPs even though the precise table holds
  at most four.
* The /stats endpoint stayed responsive throughout the table-full pressure.

The "warning is throttled to once per minute per slot" assertion lives in
the Makefile target — this script can't see the proxy's stdout from inside
its own container.
"""
import logging
import os
import re
import sys
import time

import requests

logger = logging.getLogger(__name__)


def _get(url: str) -> str:
    """Fetch a URL and return the response body.

    Args:
        url: Endpoint URL.

    Returns:
        The response text.

    Raises:
        requests.HTTPError: On non-2xx response.
    """
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_unique_ips_counter_passes_table_cap() -> None:
    """Verify cumulative unique_ips reflects all 6 source IPs past the table cap."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    expected_min = int(os.environ.get("EXPECTED_MIN_UNIQUE_IPS", "6"))

    time.sleep(1)
    metrics = _get(f"http://{host}:{stats_port}/metrics")

    match = re.search(
        r'teleproxy_secret_unique_ips\{secret="limited"\}\s+(\d+)', metrics
    )
    assert match, f"unique_ips metric not parseable:\n{metrics}"
    value = int(match.group(1))
    assert value >= expected_min, (
        f"unique_ips for 'limited' = {value}, expected >= {expected_min}\n"
        f"(Bloom-backed counter must keep incrementing once the precise "
        f"table fills — issue #71 regression)"
    )
    print(f"  unique_ips = {value} (>= {expected_min} required)")


def test_stats_endpoint_responsive() -> None:
    """Verify the /stats endpoint stayed responsive under table-full pressure."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    stats = _get(f"http://{host}:{stats_port}/stats")
    assert "secret_limited_unique_ips" in stats, (
        f"plain stats did not surface secret_limited_unique_ips:\n{stats[:500]}"
    )
    print("  /stats endpoint responsive")


def main() -> None:
    """Run the table-full regression test suite."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    tests = [
        (
            "test_unique_ips_counter_passes_table_cap",
            test_unique_ips_counter_passes_table_cap,
        ),
        ("test_stats_endpoint_responsive", test_stats_endpoint_responsive),
    ]

    print("Starting table-full regression tests...\n", flush=True)

    passed = 0
    failed = 0
    errors: list[tuple[str, BaseException]] = []

    for name, fn in tests:
        print(f"[RUN]  {name}")
        try:
            fn()
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))
        except (requests.RequestException, OSError) as e:
            logger.error("%s: network error", name, exc_info=True)
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))
        else:
            print(f"[PASS] {name}\n")
            passed += 1

    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
