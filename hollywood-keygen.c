/* Microcorruption CTF level Hollywood simple keygen */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define PWDLEN 5

uint16_t swap_bytes(uint16_t u) {
	return ((u & 0x00FF) << 8) | ((u & 0xFF00) >> 8);
}

bool
check_hash(const uint16_t *pass) {
	uint16_t r4, r6;
	r4 = r6 = 0;
	size_t rounds = PWDLEN % 2 ? PWDLEN / 2 + 1 : PWDLEN / 2;

	for (size_t i = 0; i < rounds; ++i) {
		uint16_t r5 = pass[i];
		r4 += r5;
		r4 = swap_bytes(r4);
		r6 ^= r5;
		r4 ^= r6;
		r6 ^= r4;
		r4 ^= r6;
	}

	return r4 == 0xfeb1 && r6 == 0x9298;
}

void gen() {
	uint64_t pass = 0;
	uint64_t limit = (1ULL << (PWDLEN * 8));
	unsigned counter = 0;

	for (; pass < limit; ++pass) {
		if (check_hash((uint16_t*)&pass)) {
			printf("Got password: %" PRIx64 "\n", pass);
			exit(0);
		}
		if (++counter > 0x9999999) {
			counter = 0;
			printf("Progress: %" PRIx64 "\n", pass);
		}
	}

	printf("Password of length up to %d not found\n", PWDLEN);
	exit(1);
}

int main(void) {
	gen();
}
