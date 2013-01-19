#include <stdint.h>
#include <memory.h>
#include "crypto_stream.h"
#include "api.h"
#include "camellia.h"

#define PARALLEL_BLOCKS 16
#define BLOCKSIZE 16

#define unlikely(x)	__builtin_expect((x),0)
#define likely(x)	__builtin_expect(!!(x),1)

typedef struct {
	uint64_t ll[2];
} uint128_t;

static void camellia_ctr_blk16(struct camellia_ctx *ctx, uint128_t *iv,
			       const uint8_t *in, uint8_t *out, unsigned int len)
{
	static const uint8_t bswap128[16] = { 15, 14, 13, 12, 11, 10, 9, 8,
					      7, 6, 5, 4, 3, 2, 1, 0 };
	unsigned int last_len = len % BLOCKSIZE;
	unsigned int nblocks = len / BLOCKSIZE;
	unsigned int process_blks = (len + (BLOCKSIZE - 1)) / BLOCKSIZE;
	unsigned int i;
	uint8_t lastbuf[BLOCKSIZE];
	uint8_t tmp_xmm12[BLOCKSIZE];
	uint8_t tmp_xmm13[BLOCKSIZE];
	uint8_t tmp_xmm14[BLOCKSIZE];
	uint8_t tmp_xmm15[BLOCKSIZE];

	__asm__ __volatile__ (
		"vpcmpeqd %%xmm15, %%xmm15, %%xmm15;\n"
		"vpsrldq $8, %%xmm15, %%xmm15;\n" /* low: -1, high: 0 */
		"vmovdqu %[bswap], %%xmm14;\n"
		/* load IV */
		"vmovdqu %[iv], %%xmm0;\n"
		/* IV is big-endian, byteswap for further processing */
		"vpshufb %%xmm14, %%xmm0, %%xmm13;\n"
		:
		: [bswap] "m" (*bswap128),
		  [iv] "m" (*iv)
		: "memory"
	);

#define INC_IV() \
	__asm__ __volatile__ ( \
		"vpcmpeqq %%xmm15, %%xmm13, %%xmm12;\n" \
		"vpsubq %%xmm15, %%xmm13, %%xmm13;\n" \
		"vpslldq $8, %%xmm12, %%xmm12;\n" \
		"vpsubq %%xmm12, %%xmm13, %%xmm13;\n" \
		::: \
	)

	/* %xmm0 filled, increase IV */
	INC_IV();

	/* Fill in IVs */
	do {
#define FILL_IV(n) \
	if (unlikely(process_blks == n)) \
		break; \
	__asm__ __volatile__ ("vpshufb %%xmm14, %%xmm13, %%xmm" #n ";\n":::); \
	INC_IV();

#define FILL_IV_TMP(n, xmm, tmpbuf) \
	if (unlikely(process_blks == n)) \
		break; \
	__asm__ __volatile__ ( \
		"vpshufb %%xmm14, %%xmm13, %%" #xmm ";\n" \
		"vmovdqu %%" #xmm ", %[tmp];\n" \
		: [tmp] "=m" (*(tmpbuf)) \
		:: "memory"); \
	INC_IV();

		FILL_IV(1);
		FILL_IV(2);
		FILL_IV(3);
		FILL_IV(4);
		FILL_IV(5);
		FILL_IV(6);
		FILL_IV(7);
		FILL_IV(8);
		FILL_IV(9);
		FILL_IV(10);
		FILL_IV(11);

		FILL_IV_TMP(12, xmm12, tmp_xmm12);
		FILL_IV_TMP(13, xmm12, tmp_xmm13);
		FILL_IV_TMP(14, xmm12, tmp_xmm14);
		FILL_IV_TMP(15, xmm12, tmp_xmm15);
	} while (0);

	/* Store IV */
	__asm__ __volatile__ (
		/* byteswap IV, le => be */
		"vpshufb %%xmm14, %%xmm13, %%xmm13;\n"
		"vmovdqu %%xmm13, %[iv];\n"
		: [iv] "=m" (*iv)
		:: "memory"
	);

#define LOAD_TMP(tmpbuf, xmm) \
	__asm__ __volatile__ ("vmovdqu %[tmp], %%" #xmm "\n;" ::[tmp] "m" (*(tmpbuf)) : "memory")

	if (likely(process_blks > 12)) {
		if (likely(process_blks > 13)) {
			if (likely(process_blks > 14)) {
				if (likely(process_blks > 15)) {
					LOAD_TMP(tmp_xmm15, xmm15);
				}
				LOAD_TMP(tmp_xmm14, xmm14);
			}
			LOAD_TMP(tmp_xmm13, xmm13);
		}
		LOAD_TMP(tmp_xmm12, xmm12);
	}

	__camellia_enc_blk16(ctx);

	if (in == NULL) {
		do {
#define STREAM_OUT(n, xmm) \
	if (unlikely(nblocks == n)) { \
		if (likely(last_len == 0)) \
			return; \
		out += BLOCKSIZE * n; \
		__asm__ __volatile__ ( \
			"vmovdqu %%"#xmm", %[lastbuf];\n" \
			: [lastbuf] "=m" (*lastbuf) \
			:: "memory"); \
		break; \
	} \
	__asm__ __volatile__ ( \
		"vmovdqu %%"#xmm", %[out];\n" \
		: [out] "=m" (*(out + BLOCKSIZE * n)) \
		:: "memory"); \

			STREAM_OUT(0, xmm7);
			STREAM_OUT(1, xmm6);
			STREAM_OUT(2, xmm5);
			STREAM_OUT(3, xmm4);
			STREAM_OUT(4, xmm3);
			STREAM_OUT(5, xmm2);
			STREAM_OUT(6, xmm1);
			STREAM_OUT(7, xmm0);
			STREAM_OUT(8, xmm15);
			STREAM_OUT(9, xmm14);
			STREAM_OUT(10, xmm13);
			STREAM_OUT(11, xmm12);
			STREAM_OUT(12, xmm11);
			STREAM_OUT(13, xmm10);
			STREAM_OUT(14, xmm9);
			STREAM_OUT(15, xmm8);
		} while (0);

		for (i = 0; likely(i < last_len); i++)
			out[i] = lastbuf[i];
	} else {
		do {
#define STREAM_OUT_XOR(n, xmm) \
	if (unlikely(nblocks == n)) { \
		if (likely(last_len == 0)) \
			return; \
		out += BLOCKSIZE * n; \
		in += BLOCKSIZE * n; \
		__asm__ __volatile__ ( \
			"vmovdqu %%"#xmm", %[lastbuf];\n" \
			: [lastbuf] "=m" (*lastbuf) \
			:: "memory"); \
		break; \
	} \
	__asm__ __volatile__ ( \
		"vpxor %[in], %%"#xmm", %%"#xmm";\n" \
		"vmovdqu %%"#xmm", %[out];\n" \
		: [out] "=m" (*(out + BLOCKSIZE * n)) \
		: [in] "m" (*(in + BLOCKSIZE * n)) \
		: "memory" \
		); \

			STREAM_OUT_XOR(0, xmm7);
			STREAM_OUT_XOR(1, xmm6);
			STREAM_OUT_XOR(2, xmm5);
			STREAM_OUT_XOR(3, xmm4);
			STREAM_OUT_XOR(4, xmm3);
			STREAM_OUT_XOR(5, xmm2);
			STREAM_OUT_XOR(6, xmm1);
			STREAM_OUT_XOR(7, xmm0);
			STREAM_OUT_XOR(8, xmm15);
			STREAM_OUT_XOR(9, xmm14);
			STREAM_OUT_XOR(10, xmm13);
			STREAM_OUT_XOR(11, xmm12);
			STREAM_OUT_XOR(12, xmm11);
			STREAM_OUT_XOR(13, xmm10);
			STREAM_OUT_XOR(14, xmm9);
			STREAM_OUT_XOR(15, xmm8);
		} while (0);

		for (i = 0; likely(i < last_len); i++)
			out[i] = in[i] ^ lastbuf[i];
	}
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	struct camellia_ctx ctx;
	uint128_t iv;

	camellia_init(&ctx, k, CRYPTO_KEYBYTES);
	memcpy(&iv, n, sizeof(iv));

	while (likely(inlen > 0)) {
		unsigned int process_len = likely(inlen > PARALLEL_BLOCKS * BLOCKSIZE) ?
					PARALLEL_BLOCKS * BLOCKSIZE : inlen;

		camellia_ctr_blk16(&ctx, &iv, in, out, process_len);

		inlen -= process_len;
		out += process_len;
		in += in ? process_len : 0;
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n, const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
