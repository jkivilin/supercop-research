#include "crypto_stream.h"
#include <stdlib.h>
#include "api.h"
#include "blowfish.h"

#define BLOCKSIZE 8

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	struct blowfish_ctx ctx;
	uint64_t iv, block;
	uint64_t ivs[4];

	blowfish_init(&ctx, k, CRYPTO_KEYBYTES);
	iv = __builtin_bswap64(*(uint64_t *)n); /* be => le */

	while (inlen >= BLOCKSIZE * 4) {
		ivs[0] = __builtin_bswap64(iv + 0); /* le => be */
		ivs[1] = __builtin_bswap64(iv + 1); /* le => be */
		ivs[2] = __builtin_bswap64(iv + 2); /* le => be */
		ivs[3] = __builtin_bswap64(iv + 3); /* le => be */
		iv += 4;

		blowfish_enc_blk4(&ctx, out, (uint8_t *)ivs);

		if (in) {
			((uint64_t *)out)[0] ^= ((uint64_t *)in)[0];
			((uint64_t *)out)[1] ^= ((uint64_t *)in)[1];
			((uint64_t *)out)[2] ^= ((uint64_t *)in)[2];
			((uint64_t *)out)[3] ^= ((uint64_t *)in)[3];
			in += BLOCKSIZE * 4;
		}

		out += BLOCKSIZE * 4;
		inlen -= BLOCKSIZE * 4;
	}

	if (inlen > 0) {
		unsigned int nblock = inlen / BLOCKSIZE;
		unsigned int lastlen = inlen % BLOCKSIZE;
		unsigned int i, j;

		for (i = 0; i < nblock + !!lastlen; i++)
			ivs[i] = __builtin_bswap64(iv++); /* le => be */
		for (; i < 4; i++)
			ivs[i] = 0;

		blowfish_enc_blk4(&ctx, (uint8_t *)ivs, (uint8_t *)ivs);

		if (in) {
			for (i = 0; inlen >= BLOCKSIZE; i++) {
				*(uint64_t *)out = *(uint64_t *)in ^ ivs[i];

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
