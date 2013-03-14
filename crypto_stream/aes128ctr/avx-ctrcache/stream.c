#include <stdint.h>
#include <memory.h>
#include "crypto_stream.h"
#include "api.h"
#include "aes.h"

#define PARALLEL_BLOCKS 8
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

static inline void mov128(uint128_t *dst, const uint128_t *src)
{
	__asm__ (
		"vmovdqu %[s], %%xmm0;\n"
		"vmovdqu %%xmm0, %[d];\n"
		: [d] "=m" (*dst)
		: [s] "m" (*src)
		: "xmm0", "memory"
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

/* IV must be little-endian, 'in' maybe set NULL */
extern void aes_ctr_8way(struct aes_ctx_bitslice *ctx, void *out,
			 const void *in, uint128_t *iv,
			 unsigned long num_of_chunks);

int nocache_crypto_stream_xor(struct aes_ctx_bitslice *ctx,
			      unsigned char *out, const unsigned char *in,
			      unsigned long long inlen, const unsigned char *n)
{
#define CTX_TYPE struct aes_ctx_bitslice
#define PTR_ALIGN(ptr, mask) ((void *)((((long)(ptr)) + (mask)) & ~((long)(mask))))
	const unsigned long align = 16;
	char ctxbuf[sizeof(CTX_TYPE) + align];
	CTX_TYPE *ctx = PTR_ALIGN(ctxbuf, align - 1);
	uint128_t iv;

	bswap128(&iv, (const uint128_t *)n); /* be => le */

	if (unlikely(inlen > 0)) {
		uint128_t buf[PARALLEL_BLOCKS];
		unsigned int i, j;

		aes_ctr_8way(ctx, buf, NULL, &iv, 1);

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
				mov128((uint128_t *)out, &buf[i]);

				inlen -= BLOCKSIZE;
				out += BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = ((uint8_t*)&buf[i])[j];
		}
	}

	return 0;
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
#define CTX_TYPE struct aes_ctx_bitslice
#define PTR_ALIGN(ptr, mask) ((void *)((((long)(ptr)) + (mask)) & ~((long)(mask))))
	const unsigned long align = 16;
	char ctxbuf[sizeof(CTX_TYPE) + align];
	CTX_TYPE *ctx = PTR_ALIGN(ctxbuf, align - 1);
	uint128_t iv;
	unsigned char inIV[16];
	int need_new_ctr_cache = 1;

	aes_init_bitslice(ctx, k, CRYPTO_KEYBYTES);
	bswap128(&iv, (const uint128_t *)n); /* be => le */

	/*
	 * UGLY HACK!
	 * handle short buffers through old way
	 *  &&
	 * align IV to our parallel blocks
	 */
	do {
		if (*n % PARALLEL_BLOCKS != 0 || inlen < BLOCKSIZE * PARALLEL_BLOCKS) {
			unsigned char first_byte = *n;
			unsigned int nlen = inlen;

			if (inlen >= BLOCKSIZE * PARALLEL_BLOCKS)
				nlen = (PARALLEL_BLOCKS - (first_byte % PARALLEL_BLOCKS)) *
					BLOCKSIZE;

			bswap128(&inIV, &iv);
			nocache_crypto_stream_xor(ctx, out, in, nlen,
						  (unsigned char *)&inIV);

			inlen -= nlen;
			if (inlen <= 0)
				return 0;

			add128(&iv, (PARALLEL_BLOCKS - (first_byte % PARALLEL_BLOCKS)));
			out += nlen;
			in += in ? nlen : 0;
		}
	} while (inlen < BLOCKSIZE * PARALLEL_BLOCKS);

	/*
	 * IV is now aligned to our PARALLEL_BLOCKS
	 */
	do {
		uint8_t ctr_byte = ((uint8_t *)&iv)[0]; /* le */

		if (unlikely(ctr_byte == 0x00))
			need_new_ctr_cache = 1;

		if (unlikely(need_new_ctr_cache)) {
			bswap128(&inIV, &iv); /* le => be */

			/*
			 * ctr-cache has to be updated
			 */
			need_new_ctr_cache = 0;
			aes_get_counter_cache_bitslice(&ctx->ctx, ctr_cache, &inIV);
		}

		aes_ctrcached_8way(ctx, out, in, ctr_cache, ctr_byte);

		add128(&iv, &iv, PARALLEL_BLOCKS);
	} while (inlen >= BLOCKSIZE * PARALLEL_BLOCKS);

	bswap128(&inIV, &iv);
	nocache_crypto_stream_xor(ctx, out, in, nlen,
				  (unsigned char *)&inIV);
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n, const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
