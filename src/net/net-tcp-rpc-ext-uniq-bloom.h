#pragma once

void uniq_bloom_clear_slot (int sid);
int uniq_bloom_test_and_set (int sid, unsigned ip, const unsigned char *ipv6);
