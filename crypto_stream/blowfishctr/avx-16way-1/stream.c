#include "crypto_stream.h"
#include <stdlib.h>
#include "api.h"
#include "blowfish.h"

#define unlikely(x)	(!__builtin_expect(!(x),1))
#define likely(x)	(__builtin_expect(!!(x),1))

#define BLOCKSIZE 8

extern void __blowfish_enc_blk_16way(struct blowfish_ctx *ctx, uint8_t *dst, const uint8_t *src, char xor);

static inline void bswap64(uint64_t *dst, const uint64_t *src)
{
	*dst = __builtin_bswap64(*src);
}

static inline void add64(uint64_t *dst, const uint64_t *src, uint64_t add)
{
	*dst = *src + add;
}

static inline void inc64(uint64_t *dst)
{
	add64(dst, dst, 1);
}

static inline void xor64(uint64_t *dst, const uint64_t *src1, const uint64_t *src2)
{
	*dst = *src1 ^ *src2;
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	char ctrbuf[sizeof(struct blowfish_ctx) + 16];
	struct blowfish_ctx *ctx = (void *)((unsigned long)ctrbuf & ~0xfULL);
	uint64_t iv;
	uint64_t ivs[16];
	unsigned int i;

	blowfish_init(ctx, k, CRYPTO_KEYBYTES);
	bswap64(&iv, (const uint64_t *)n); /* be => le */

	while (likely(inlen >= BLOCKSIZE * 16)) {
		bswap64(&ivs[0], &iv); /* le => be */
		for (i = 1; i < 16; i++) {
			add64(&ivs[i], &iv, i);
			bswap64(&ivs[i], &ivs[i]); /* le => be */
		}
		add64(&iv, &iv, 16);

		__blowfish_enc_blk_16way(ctx, out, (uint8_t *)ivs, 0);

		if (unlikely(in)) {
			for (i = 0; i < 16; i++)
				xor64(&((uint64_t *)out)[i], &((uint64_t *)out)[i], &((uint64_t *)in)[i]);
			in += BLOCKSIZE * 16;
		}

		out += BLOCKSIZE * 16;
		inlen -= BLOCKSIZE * 16;
	}

	if (unlikely(inlen > 0)) {
		unsigned int nblock = inlen / BLOCKSIZE;
		unsigned int lastlen = inlen % BLOCKSIZE;
		unsigned int j;

		for (i = 0; i < nblock + !!lastlen; i++) {
			bswap64(&ivs[i], &iv); /* le => be */
			inc64(&iv);
		}
		for (; i < 16; i++) {
			ivs[i] = 0;
		}

		__blowfish_enc_blk_16way(ctx, (uint8_t *)ivs, (uint8_t *)ivs, 0);

		if (in) {
			for (i = 0; inlen >= BLOCKSIZE; i++) {
				xor64((uint64_t *)out, (uint64_t *)in, &ivs[i]);

				inlen -= BLOCKSIZE;
				in += BLOCKSIZE;
				out += BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = in[j] ^ ((uint8_t*)&ivs[i])[j];
		} else {
			for (i = 0; inlen >= BLOCKSIZE; i++) {
				*(uint64_t *)out = ivs[i];

				inlen -= BLOCKSIZE;
				out += BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = ((uint8_t*)&ivs[i])[j];
		}
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n,const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
