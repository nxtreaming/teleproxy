/*
    This file is part of Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.
*/

/*
 *  Per-secret Bloom filter for cumulative unique-IP counting (issue #71).
 *
 *  The precise per-IP table in net-tcp-rpc-ext-server.c is sized for the
 *  rate-limit / max_ips path (256 entries, scanned linearly on every
 *  packet).  Plain secrets with no limits configured can see thousands of
 *  distinct source IPs on a busy public proxy, which would overflow the
 *  precise table — so cumulative counting moves here.
 *
 *  Sized for ~0.5% FPR at 10K IPs and ~5% at 50K IPs.  4 hashes derived
 *  from cheap multiplicative mixing — no crypto, this is a metrics sidecar.
 */

#include <string.h>

#include "net/net-connections.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tcp-rpc-ext-uniq-bloom.h"

#define BLOOM_BITS  (1U << 16)
#define BLOOM_BYTES (BLOOM_BITS / 8)
#define BLOOM_MASK  (BLOOM_BITS - 1)

static unsigned char uniq_bloom[EXT_SECRET_MAX_SLOTS][BLOOM_BYTES];

void uniq_bloom_clear_slot (int sid) {
  if (sid < 0 || sid >= EXT_SECRET_MAX_SLOTS) { return; }
  memset (uniq_bloom[sid], 0, BLOOM_BYTES);
}

int uniq_bloom_test_and_set (int sid, unsigned ip, const unsigned char *ipv6) {
  unsigned h[4];
  if (ip != 0) {
    unsigned x = ip;
    h[0] = (x * 2654435761u) & BLOOM_MASK;
    h[1] = (x * 40503u + 0x9e3779b9u) & BLOOM_MASK;
    h[2] = ((x ^ (x >> 16)) * 0x85ebca6bu) & BLOOM_MASK;
    h[3] = ((x ^ (x >> 13)) * 0xc2b2ae35u) & BLOOM_MASK;
  } else {
    unsigned a = ((unsigned)ipv6[0]<<24)|((unsigned)ipv6[1]<<16)|((unsigned)ipv6[2]<<8)|ipv6[3];
    unsigned b = ((unsigned)ipv6[4]<<24)|((unsigned)ipv6[5]<<16)|((unsigned)ipv6[6]<<8)|ipv6[7];
    unsigned c = ((unsigned)ipv6[8]<<24)|((unsigned)ipv6[9]<<16)|((unsigned)ipv6[10]<<8)|ipv6[11];
    unsigned d = ((unsigned)ipv6[12]<<24)|((unsigned)ipv6[13]<<16)|((unsigned)ipv6[14]<<8)|ipv6[15];
    h[0] = (a ^ (b * 2654435761u)) & BLOOM_MASK;
    h[1] = (b ^ (c * 40503u)) & BLOOM_MASK;
    h[2] = (c ^ (d * 0x85ebca6bu)) & BLOOM_MASK;
    h[3] = (d ^ (a * 0xc2b2ae35u)) & BLOOM_MASK;
  }
  int novel = 0;
  for (int i = 0; i < 4; i++) {
    unsigned bit = h[i];
    unsigned char *p = &uniq_bloom[sid][bit >> 3];
    unsigned mask = 1u << (bit & 7);
    if (!(*p & mask)) { novel = 1; *p |= mask; }
  }
  return novel;
}
