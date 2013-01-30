#include <stdint.h>
#include <memory.h>
#include "crypto_stream.h"
#include "api.h"
#include "camellia.h"

#define PARALLEL_BLOCKS 16
#define BLOCKSIZE 16

#define unlikely(x)	(!__builtin_expect(!(x),1))
#define likely(x)	(__builtin_expect(!!(x),1))

typedef struct {
	uint64_t ll[2];
} uint128_t;

static inline void bswap128(uint128_t *dst, const uint128_t *src)
{
	uint64_t tmp;

	tmp = __builtin_bswap64(src->ll[1]);
	dst->ll[1] = __builtin_bswap64(src->ll[0]);
	dst->ll[0] = tmp;
}

static inline void inc128(uint128_t *u)
{
	__asm__ (
		"addq $1, %[ll0];\n"
		"adcq $0, %[ll1];\n"
		: [ll0] "=g" (u->ll[0]), [ll1] "=g" (u->ll[1])
		: "0" (u->ll[0]), "1" (u->ll[1])
		:
	);
}

static inline void add128(uint128_t *dst, const uint128_t *src, uint64_t add)
{
	__asm__ (
		"addq %[add], %[ll0];\n"
		"adcq $0, %[ll1];\n"
		: [ll0] "=g" (dst->ll[0]), [ll1] "=g" (dst->ll[1])
		: "0" (src->ll[0]), "1" (src->ll[1]), [add] "cg" (add)
		:
	);
}

static inline void xor128(uint128_t *dst, const uint128_t *src1, const uint128_t *src2)
{
	__asm__ (
		"vmovdqu %[s1], %%xmm0;\n"
		"vpxor %[s2], %%xmm0, %%xmm0;\n"
		"vmovdqu %%xmm0, %[d];\n"
		: [d] "=m" (*dst)
		: [s1] "m" (*src1), [s2] "m" (*src2)
		: "xmm0", "memory"
	);
}

/* IV must be little-endian, 'in' maybe set NULL */
extern void camellia_ctr_16way(struct camellia_ctx *ctx, void *out, const void *in, uint128_t *iv);

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	struct camellia_ctx ctx;
	uint128_t iv;

	if (1) /*camellia-256-ctr disabled*/
		return 1;

	camellia_init(&ctx, k, CRYPTO_KEYBYTES);
	bswap128(&iv, (const uint128_t *)n); /* be => le */

	while (likely(inlen >= PARALLEL_BLOCKS * BLOCKSIZE)) {
		camellia_ctr_16way(&ctx, out, in, &iv);

		inlen -= PARALLEL_BLOCKS * BLOCKSIZE;
		out += PARALLEL_BLOCKS * BLOCKSIZE;
		in += unlikely(in) ? PARALLEL_BLOCKS * BLOCKSIZE : 0;
	}

	if (unlikely(inlen > 0)) {
		uint128_t buf[PARALLEL_BLOCKS];
		unsigned int i, j;

		camellia_ctr_16way(&ctx, buf, NULL, &iv);

		if (in) {
			for (i = 0; inlen >= BLOCKSIZE; i++) {
				xor128((uint128_t *)out, (uint128_t *)in, &buf[i]);

				inlen -= BLOCKSIZE;
				in += BLOCKSIZE;
				out += BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = in[j] ^ ((uint8_t*)&buf[i])[j];
		} else {
			for (i = 0; inlen >= BLOCKSIZE; i++) {
				*(uint128_t *)out = buf[i];

				inlen -= BLOCKSIZE;
				out += BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = ((uint8_t*)&buf[i])[j];
		}
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n, const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
