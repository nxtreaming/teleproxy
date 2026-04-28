#!/usr/bin/env python3
"""Drive a single obfs2 init then exit.

Used as the worker container for the unique-ips test rig — each instance
runs from a distinct ipv4_address so the proxy's per-secret unique-IP
counter increments. A bare TLS handshake doesn't trigger the increment
(secret identification happens after the obfs2 header arrives), so we send
the obfs2 init that test_cdn_dc.py already proved triggers the path.
"""
import logging
import os
import socket
import sys
import time

logger = logging.getLogger(__name__)


def build_obfs2_init(secret_hex: str, target_dc: int = 2) -> bytes:
    """Build a 64-byte obfs2 init header that identifies the given secret.

    Args:
        secret_hex: 32-char hex secret (no `dd` prefix; this function adds it).
        target_dc: Target DC ID for the proxy to attempt routing to.

    Returns:
        The encrypted 64-byte init header.
    """
    from telethon.network.connection.tcpmtproxy import MTProxyIO
    from telethon.network.connection.tcpintermediate import (
        RandomizedIntermediatePacketCodec,
    )

    secret = bytes.fromhex("dd" + secret_hex)
    header, _enc, _dec = MTProxyIO.init_header(
        secret, target_dc, RandomizedIntermediatePacketCodec
    )
    return header


def wait_for_tcp(host: str, port: int, timeout: int = 90) -> bool:
    """Poll until the proxy accepts a TCP connection on the given port.

    Args:
        host: Proxy hostname.
        port: Proxy port.
        timeout: Maximum seconds to wait.

    Returns:
        True if the port becomes reachable, False on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return True
        except OSError:
            time.sleep(1)
    return False


def main() -> None:
    """Send one obfs2 init from this container's source IP and exit."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    if not secret_hex:
        print("ERROR: TELEPROXY_SECRET not set", flush=True)
        sys.exit(1)

    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_tcp(host, port):
        print("ERROR: Proxy not reachable after 90s", flush=True)
        sys.exit(1)

    header = build_obfs2_init(secret_hex, target_dc=2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((host, port))
        s.sendall(header)
        # Give the proxy time to parse the header and increment the counters.
        time.sleep(2)
    except OSError as e:
        logger.error("obfs2 init: socket error", exc_info=True)
        print(f"ERROR: obfs2 init failed: {e}", flush=True)
        sys.exit(1)
    finally:
        s.close()

    print("obfs2 init sent", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
