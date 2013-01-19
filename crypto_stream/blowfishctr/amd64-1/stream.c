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
	uint64_t iv;
	uint64_t block;

	blowfish_init(&ctx, k, CRYPTO_KEYBYTES);
	iv = __builtin_bswap64(*(uint64_t *)n); /* be => le */

	while (inlen > 0) {
		block = __builtin_bswap64(iv++); /* le => be */

		block = blowfish_enc_blk(&ctx, block);
		if (inlen < BLOCKSIZE)
			break;

		if (in) {
			*(uint64_t *)out = *(uint64_t *)in ^ block;
			in += BLOCKSIZE;
		} else {
			*(uint64_t *)out = block;
		}

		out += BLOCKSIZE;
		inlen -= BLOCKSIZE;
	}

	if (inlen > 0) {
		/* handle remaining bytes */
		unsigned int i;

		if (in) {
			for (i = 0; i < inlen; i++)
				out[i] = in[i] ^ ((uint8_t*)&block)[i];
		} else {
			for (i = 0; i < inlen; i++)
				out[i] = ((uint8_t*)&block)[i];
		}
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n,const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}