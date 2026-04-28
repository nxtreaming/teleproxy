#!/usr/bin/env python3
"""E2E test for per-secret unique_ips counter (issue #70).

Verifies that teleproxy_secret_unique_ips increments for plain secrets
(no rate_limit, no max_ips) — the regression case where ip_track_connect
used to early-return and never populate the counter. The compose rig drives
3 distinct source IPs into the proxy before this verifier runs.
"""
import logging
import os
import re
import sys
import time

import requests

logger = logging.getLogger(__name__)


def _get_metrics(host: str, stats_port: str) -> str:
    """Fetch Prometheus metrics from the proxy.

    Args:
        host: Proxy hostname or IP.
        stats_port: Stats endpoint port.

    Returns:
        The /metrics body as text.
    """
    url = f"http://{host}:{stats_port}/metrics"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_unique_ips_metric_present() -> None:
    """Verify teleproxy_secret_unique_ips is exposed for the plain secret."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    metrics = _get_metrics(host, stats_port)

    assert 'teleproxy_secret_unique_ips{secret="plain"}' in metrics, (
        f"unique_ips metric for 'plain' secret missing:\n{metrics}"
    )
    print("  unique_ips metric exposed for 'plain' secret")


def test_unique_ips_reflects_distinct_sources() -> None:
    """Verify unique_ips reflects the distinct source IPs that handshook."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    expected_min = int(os.environ.get("EXPECTED_MIN_UNIQUE_IPS", "3"))

    # Allow stats to settle after the handshake containers exit.
    time.sleep(1)
    metrics = _get_metrics(host, stats_port)

    match = re.search(
        r'teleproxy_secret_unique_ips\{secret="plain"\}\s+(\d+)', metrics
    )
    assert match, f"unique_ips metric not parseable:\n{metrics}"
    value = int(match.group(1))
    assert value >= expected_min, (
        f"unique_ips for 'plain' = {value}, expected >= {expected_min}\n"
        f"(this is the #70 regression — counter stuck at 0 for plain secrets)"
    )
    print(f"  unique_ips = {value} (>= {expected_min} required)")


def test_unique_ips_in_plain_stats() -> None:
    """Verify the plain-text /stats output also surfaces unique_ips."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    expected_min = int(os.environ.get("EXPECTED_MIN_UNIQUE_IPS", "3"))

    url = f"http://{host}:{stats_port}/stats"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    stats = resp.text

    match = re.search(r"secret_plain_unique_ips\s+(\d+)", stats)
    assert match, f"secret_plain_unique_ips not found in /stats:\n{stats}"
    value = int(match.group(1))
    assert value >= expected_min, (
        f"secret_plain_unique_ips = {value}, expected >= {expected_min}"
    )
    print(f"  /stats: secret_plain_unique_ips = {value}")


def main() -> None:
    """Run the unique_ips counter regression test suite."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    tests = [
        ("test_unique_ips_metric_present", test_unique_ips_metric_present),
        (
            "test_unique_ips_reflects_distinct_sources",
            test_unique_ips_reflects_distinct_sources,
        ),
        ("test_unique_ips_in_plain_stats", test_unique_ips_in_plain_stats),
    ]

    print("Starting unique_ips counter tests...\n", flush=True)

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
