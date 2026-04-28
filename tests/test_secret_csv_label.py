#!/usr/bin/env python3
"""E2E test for SECRET=hex:label CSV parsing in start.sh (issue #67).

Verifies that the comma-separated SECRET env var splits each entry on `:`
and writes the second field as a separate `label` line in the generated TOML
config — surfaced through Prometheus labels and the plain-text /stats output.
"""
import logging
import os
import sys
import time

import requests

from test_tls_e2e import wait_for_proxy

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


def _get_stats(host: str, stats_port: str) -> str:
    """Fetch plain-text /stats output.

    Args:
        host: Proxy hostname or IP.
        stats_port: Stats endpoint port.

    Returns:
        The /stats body as text.
    """
    url = f"http://{host}:{stats_port}/stats"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_labels_in_prometheus_metrics() -> None:
    """Verify both labels surface as `secret="family"` / `secret="friends"`."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    metrics = _get_metrics(host, stats_port)

    assert 'secret="family"' in metrics, (
        f'Expected secret="family" label in /metrics:\n{metrics}'
    )
    assert 'secret="friends"' in metrics, (
        f'Expected secret="friends" label in /metrics:\n{metrics}'
    )
    # Sanity: the bug would emit secret="hexstring:family" — verify the colon-bearing label is absent.
    assert ":family" not in metrics, (
        f"Label still contains raw hex:label form (parser bug regressed):\n{metrics}"
    )
    print("  Prometheus: family/friends labels exposed correctly")


def test_labels_in_plain_stats() -> None:
    """Verify per-secret stats lines use `secret_family_*` / `secret_friends_*` keys."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    stats = _get_stats(host, stats_port)

    assert "secret_family_connections\t" in stats, (
        f"Expected secret_family_connections in /stats:\n{stats}"
    )
    assert "secret_friends_connections\t" in stats, (
        f"Expected secret_friends_connections in /stats:\n{stats}"
    )
    print("  Plain stats: family/friends keys present")


def main() -> None:
    """Run the CSV-label parser regression test suite."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    tests = [
        ("test_labels_in_prometheus_metrics", test_labels_in_prometheus_metrics),
        ("test_labels_in_plain_stats", test_labels_in_plain_stats),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting CSV secret-label tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

    time.sleep(2)

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
