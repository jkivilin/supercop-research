#include <openssl/aes.h>
#include <stdint.h>
#include <memory.h>
#include <assert.h>
#include "crypto_stream.h"
#include "api.h"

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n, const unsigned char *k)
{
	static const uint64_t zero[(1024 * 1024) / sizeof(uint64_t)];
	unsigned char tmp[AES_BLOCK_SIZE] = {0, };
	unsigned char iv[AES_BLOCK_SIZE];
	AES_KEY ctx;
	unsigned int num = 0;

	if (/*disabled*/1)
		return 1;

	assert(outlen <= sizeof(zero));

	AES_set_encrypt_key(k, CRYPTO_KEYBYTES * 8, &ctx);
	memcpy(iv, n, sizeof(iv));

	AES_ctr128_encrypt((void *)zero, out, outlen, &ctx, iv, tmp, &num);

	return 0;
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	unsigned char tmp[AES_BLOCK_SIZE] = {0, };
	unsigned char iv[AES_BLOCK_SIZE];
	AES_KEY ctx;
	unsigned int num = 0;

	AES_set_encrypt_key(k, CRYPTO_KEYBYTES * 8, &ctx);
	memcpy(iv, n, sizeof(iv));

	AES_ctr128_encrypt(in, out, inlen, &ctx, iv, tmp, &num);

	return 0;
}
