// Black-box differential test for Monocypher PR #299.
//
// Links master's monocypher.c (every public symbol prefixed old_, see
// run.sh) with the PR's monocypher.c, and checks that
// crypto_eddsa_check_equation() returns the same verdict in both on:
//
//   1. the vectors from verify_pr299.py (cofactored accepts with
//      small-order and non-canonical A and R, S >= L, off-curve
//      encodings, random rejects), where a third, independent affine
//      implementation also fixed the expected verdict;
//   2. fresh key pairs and signatures (old == new == accept), every
//      single-byte and single-bit corruption of those signatures and
//      public keys, and random inputs.
//
// Build and run with ./run.sh from a Monocypher checkout.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "pr299_vectors.h"

int  old_crypto_eddsa_check_equation(const uint8_t signature[64],
                                     const uint8_t public_key[32],
                                     const uint8_t h[32]);
int  old_crypto_eddsa_check(const uint8_t signature[64],
                            const uint8_t public_key[32],
                            const uint8_t *message, size_t message_size);
void old_crypto_eddsa_key_pair(uint8_t secret_key[64], uint8_t public_key[32],
                               uint8_t seed[32]);
void old_crypto_eddsa_sign(uint8_t signature[64], const uint8_t secret_key[64],
                           const uint8_t *message, size_t message_size);

static uint64_t rng_state = 0x299299299299ULL;
static uint64_t rng64(void)                       // splitmix64
{
	uint64_t z = (rng_state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}
static void rng_fill(uint8_t *buf, size_t n)
{
	for (size_t i = 0; i < n; i++) { buf[i] = (uint8_t)rng64(); }
}

static long checks = 0, accepts = 0;

static void same_equation(const uint8_t sig[64], const uint8_t pk[32],
                          const uint8_t h[32], int expected, const char *what)
{
	int o = old_crypto_eddsa_check_equation(sig, pk, h);
	int n =     crypto_eddsa_check_equation(sig, pk, h);
	checks++;
	if (o == 0) { accepts++; }
	if (o != n || (expected != 2 && o != expected)) {
		fprintf(stderr, "MISMATCH (%s): old %d, new %d, expected %d\n",
		        what, o, n, expected);
		exit(1);
	}
}

static void same_check(const uint8_t sig[64], const uint8_t pk[32],
                       const uint8_t *msg, size_t len, int expected,
                       const char *what)
{
	int o = old_crypto_eddsa_check(sig, pk, msg, len);
	int n =     crypto_eddsa_check(sig, pk, msg, len);
	checks++;
	if (o == 0) { accepts++; }
	if (o != n || (expected != 2 && o != expected)) {
		fprintf(stderr, "MISMATCH (%s): old %d, new %d, expected %d\n",
		        what, o, n, expected);
		exit(1);
	}
}

int main(void)
{
	// 1. Independently generated vectors (expected verdict included)
	size_t nv = sizeof(pr299_vectors) / sizeof(pr299_vectors[0]);
	for (size_t i = 0; i < nv; i++) {
		const pr299_vec *v = &pr299_vectors[i];
		same_equation(v->sig, v->pk, v->h, v->expected, "python vector");
	}
	printf("vectors:   %zu cases, old == new == reference\n", nv);

	// 2. Real signatures, and every small corruption of them
	long before = checks;
	for (int i = 0; i < 200; i++) {
		uint8_t seed[32], seed2[32], sk[64], pk[32], sig[64], msg[64];
		rng_fill(seed, 32);
		memcpy(seed2, seed, 32);            // key_pair wipes the seed
		rng_fill(msg, sizeof msg);
		size_t len = (size_t)(rng64() % (sizeof msg + 1));
		crypto_eddsa_key_pair(sk, pk, seed);
		crypto_eddsa_sign(sig, sk, msg, len);
		{   // old and new must still agree on how to sign (sanity)
			uint8_t sk2[64], pk2[32], sig2[64];
			old_crypto_eddsa_key_pair(sk2, pk2, seed2);
			old_crypto_eddsa_sign(sig2, sk2, msg, len);
			if (memcmp(pk, pk2, 32) || memcmp(sig, sig2, 64)) {
				fprintf(stderr, "signing differs?!\n"); return 1;
			}
		}
		same_check(sig, pk, msg, len, 0, "valid signature");

		// every single-byte +1, and every single-bit flip, in sig and pk
		for (int j = 0; j < 64 + 32; j++) {
			uint8_t s2[64], p2[32];
			memcpy(s2, sig, 64); memcpy(p2, pk, 32);
			if (j < 64) { s2[j] += 1; } else { p2[j - 64] += 1; }
			same_check(s2, p2, msg, len, 2, "byte+1");
			for (int b = 0; b < 8; b++) {
				memcpy(s2, sig, 64); memcpy(p2, pk, 32);
				if (j < 64) { s2[j] ^= 1 << b; } else { p2[j - 64] ^= 1 << b; }
				same_check(s2, p2, msg, len, 2, "bit flip");
			}
		}
		// message tampered
		if (len > 0) {
			msg[rng64() % len] ^= 1;
			same_check(sig, pk, msg, len, -1, "message tampered");
		}
	}
	printf("mutations: %ld cases, old == new\n", checks - before);

	// 3. Random garbage straight into check_equation (h reduced mod L,
	//    as crypto_eddsa_check does before calling it)
	before = checks;
	for (int i = 0; i < 20000; i++) {
		uint8_t sig[64], pk[32], h64[64], h[32];
		rng_fill(sig, 64); rng_fill(pk, 32); rng_fill(h64, 64);
		crypto_eddsa_reduce(h, h64);
		if (rng64() & 1) {         // sometimes a plausible pk and R
			uint8_t k[32];
			rng_fill(k, 32);
			crypto_eddsa_scalarbase(pk, k);
			rng_fill(k, 32);
			crypto_eddsa_scalarbase(sig, k);
		}
		if (rng64() & 1) { sig[63] &= 0x0f; }   // sometimes s < L
		same_equation(sig, pk, h, 2, "random");
	}
	printf("random:    %ld cases, old == new\n", checks - before);

	printf("total:     %ld checks, %ld accepted by both, 0 mismatches\n",
	       checks, accepts);
	return 0;
}
