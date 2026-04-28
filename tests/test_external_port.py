#!/usr/bin/env python3
"""E2E test for EXTERNAL_PORT advertised in /link page (issue #66).

Verifies that when EXTERNAL_PORT differs from PORT, the connection-link URL
embedded in the /link HTML page reports the external port — so users behind
Docker `-p host:container` mappings get a usable t.me/proxy?... link.
"""
import logging
import os
import re
import sys
import time

import requests

logger = logging.getLogger(__name__)


def _wait_for_stats(host: str, stats_port: str, timeout: int = 60) -> None:
    """Block until the /stats endpoint responds or raise.

    Args:
        host: Proxy hostname or IP.
        stats_port: Stats endpoint port.
        timeout: Maximum seconds to wait.

    Raises:
        TimeoutError: If the proxy stats endpoint is not ready in time.
    """
    deadline = time.time() + timeout
    last_err: BaseException | None = None
    while time.time() < deadline:
        try:
            resp = requests.get(f"http://{host}:{stats_port}/stats", timeout=2)
            if resp.status_code == 200:
                return
        except (requests.RequestException, OSError) as exc:
            last_err = exc
        time.sleep(1)
    raise TimeoutError(f"proxy stats not ready after {timeout}s: {last_err}")


def _get_link_page(host: str, stats_port: str) -> str:
    """Fetch the /link HTML page from the proxy.

    Args:
        host: Proxy hostname or IP.
        stats_port: Stats endpoint port.

    Returns:
        The /link body as text.
    """
    url = f"http://{host}:{stats_port}/link"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_link_page_advertises_external_port() -> None:
    """Verify the /link page shows the EXTERNAL_PORT in t.me/proxy URLs."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    expected = os.environ.get("EXPECTED_PORT", "4443")

    body = _get_link_page(host, stats_port)

    matches = re.findall(r"t\.me/proxy\?[^\"<>\s]*port=(\d+)", body)
    assert matches, f"No t.me/proxy URLs found in /link page:\n{body[:1000]}"

    for found in matches:
        assert found == expected, (
            f"/link advertises port={found}, expected {expected}\n"
            f"Body excerpt:\n{body[:1000]}"
        )
    print(f"  /link advertises port={expected} in {len(matches)} URL(s)")


def test_link_page_advertises_external_port_in_tg_url() -> None:
    """Verify the tg://proxy URL also uses EXTERNAL_PORT."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    expected = os.environ.get("EXPECTED_PORT", "4443")

    body = _get_link_page(host, stats_port)

    matches = re.findall(r"tg://proxy\?[^\"<>\s]*port=(\d+)", body)
    assert matches, f"No tg://proxy URLs found in /link page:\n{body[:1000]}"

    for found in matches:
        assert found == expected, (
            f"tg://proxy advertises port={found}, expected {expected}"
        )
    print(f"  tg://proxy advertises port={expected} in {len(matches)} URL(s)")


def main() -> None:
    """Run the EXTERNAL_PORT regression test suite."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    tests = [
        ("test_link_page_advertises_external_port", test_link_page_advertises_external_port),
        (
            "test_link_page_advertises_external_port_in_tg_url",
            test_link_page_advertises_external_port_in_tg_url,
        ),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    print("Starting EXTERNAL_PORT tests...\n", flush=True)
    print(f"Waiting for proxy stats at {host}:{stats_port}...", flush=True)
    try:
        _wait_for_stats(host, stats_port, timeout=90)
    except TimeoutError as e:
        print(f"ERROR: {e}", flush=True)
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

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
