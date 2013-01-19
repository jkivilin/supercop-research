#include "crypto_stream.h"
#include <stdlib.h>
#include "api.h"
#include "twofish.h"

#define BLOCKSIZE 16

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
	if (u->ll[0]++ == -1LL)
		u->ll[1]++;
}

static inline void add128(uint128_t *dst, const uint128_t *src, uint64_t add)
{
	add += src->ll[0];
	dst->ll[1] = src->ll[1] + (src->ll[0] > add);
	dst->ll[0] = add;
}

static inline void xor128(uint128_t *dst, const uint128_t *src1, const uint128_t *src2)
{
	dst->ll[0] = src1->ll[0] ^ src2->ll[0];
	dst->ll[1] = src1->ll[1] ^ src2->ll[1];
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	struct twofish_ctx ctx;
	uint128_t iv;
	uint128_t ivs[3];

	twofish_init(&ctx, k, CRYPTO_KEYBYTES);
	bswap128(&iv, (const uint128_t *)n); /* be => le */

	while (inlen >= BLOCKSIZE * 3) {
		bswap128(&ivs[0], &iv); /* le => be */
		add128(&ivs[1], &iv, 1);
		bswap128(&ivs[1], &ivs[1]); /* le => be */
		add128(&ivs[2], &iv, 2);
		bswap128(&ivs[2], &ivs[2]); /* le => be */
		add128(&iv, &iv, 3);

		twofish_enc_blk3(&ctx, out, (uint8_t *)ivs);

		if (in) {
			xor128(&((uint128_t *)out)[0], &((uint128_t *)out)[0], &((uint128_t *)in)[0]);
			xor128(&((uint128_t *)out)[1], &((uint128_t *)out)[1], &((uint128_t *)in)[1]);
			xor128(&((uint128_t *)out)[2], &((uint128_t *)out)[2], &((uint128_t *)in)[2]);
			in += BLOCKSIZE * 3;
		}

		out += BLOCKSIZE * 3;
		inlen -= BLOCKSIZE * 3;
	}

	if (inlen > 0) {
		unsigned int nblock = inlen / BLOCKSIZE;
		unsigned int lastlen = inlen % BLOCKSIZE;
		unsigned int i, j;

		for (i = 0; i < nblock + !!lastlen; i++) {
			bswap128(&ivs[i], &iv); /* le => be */
			inc128(&iv);
		}
		for (; i < 3; i++) {
			ivs[i].ll[0] = 0;
			ivs[i].ll[1] = 0;
		}

		twofish_enc_blk3(&ctx, (uint8_t *)ivs, (uint8_t *)ivs);

		if (in) {
			for (i = 0; inlen >= BLOCKSIZE; i++) {
				xor128((uint128_t *)out, (uint128_t *)in, &ivs[i]);

				inlen -= BLOCKSIZE;
				in += BLOCKSIZE;
				out += BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = in[j] ^ ((uint8_t*)&ivs[i])[j];
		} else {
			for (i = 0; inlen >= BLOCKSIZE; i++) {
				*(uint128_t *)out = ivs[i];

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
