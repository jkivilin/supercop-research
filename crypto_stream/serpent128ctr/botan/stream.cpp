#include <botan/botan.h>
#include <botan/serp_simd.h>
#include <botan/ctr.h>
#include <assert.h>
#include "crypto_stream.h"
#include "api.h"

Botan::LibraryInitializer __init();

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	Botan::CTR_BE ctrmode(new Botan::Serpent_SIMD());

	ctrmode.set_key(k, CRYPTO_KEYBYTES);
	ctrmode.set_iv(n, CRYPTO_NONCEBYTES);

	ctrmode.cipher(in, out, inlen);

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n, const unsigned char *k)
{
	static const unsigned char zero[1024 * 1024] = {0, };

	assert(sizeof(zero) >= outlen);

	return crypto_stream_xor(out, zero, outlen, n, k);
}
