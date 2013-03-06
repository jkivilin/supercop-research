/*
 * aes.c - implementation of AES / Rijndael, from PuTTY (and heavily modified)
 */
/*
 * Original license:
 *
 *  PuTTY is copyright 1997-2012 Simon Tatham.
 *
 *  Portions copyright Robert de Bath, Joris van Rantwijk, Delian Delchev,
 *  Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry, Justin Bradford,
 *  Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus Kuhn, Colin Watson, and
 *  CORE SDI S.A.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 *  SIMON TATHAM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include "aes.h"

const uint32_t sboxtable[256 + 1] = {
	0x00000000,
	0x00000063, 0x0000007c, 0x00000077, 0x0000007b,
	0x000000f2, 0x0000006b, 0x0000006f, 0x000000c5,
	0x00000030, 0x00000001, 0x00000067, 0x0000002b,
	0x000000fe, 0x000000d7, 0x000000ab, 0x00000076,
	0x000000ca, 0x00000082, 0x000000c9, 0x0000007d,
	0x000000fa, 0x00000059, 0x00000047, 0x000000f0,
	0x000000ad, 0x000000d4, 0x000000a2, 0x000000af,
	0x0000009c, 0x000000a4, 0x00000072, 0x000000c0,
	0x000000b7, 0x000000fd, 0x00000093, 0x00000026,
	0x00000036, 0x0000003f, 0x000000f7, 0x000000cc,
	0x00000034, 0x000000a5, 0x000000e5, 0x000000f1,
	0x00000071, 0x000000d8, 0x00000031, 0x00000015,
	0x00000004, 0x000000c7, 0x00000023, 0x000000c3,
	0x00000018, 0x00000096, 0x00000005, 0x0000009a,
	0x00000007, 0x00000012, 0x00000080, 0x000000e2,
	0x000000eb, 0x00000027, 0x000000b2, 0x00000075,
	0x00000009, 0x00000083, 0x0000002c, 0x0000001a,
	0x0000001b, 0x0000006e, 0x0000005a, 0x000000a0,
	0x00000052, 0x0000003b, 0x000000d6, 0x000000b3,
	0x00000029, 0x000000e3, 0x0000002f, 0x00000084,
	0x00000053, 0x000000d1, 0x00000000, 0x000000ed,
	0x00000020, 0x000000fc, 0x000000b1, 0x0000005b,
	0x0000006a, 0x000000cb, 0x000000be, 0x00000039,
	0x0000004a, 0x0000004c, 0x00000058, 0x000000cf,
	0x000000d0, 0x000000ef, 0x000000aa, 0x000000fb,
	0x00000043, 0x0000004d, 0x00000033, 0x00000085,
	0x00000045, 0x000000f9, 0x00000002, 0x0000007f,
	0x00000050, 0x0000003c, 0x0000009f, 0x000000a8,
	0x00000051, 0x000000a3, 0x00000040, 0x0000008f,
	0x00000092, 0x0000009d, 0x00000038, 0x000000f5,
	0x000000bc, 0x000000b6, 0x000000da, 0x00000021,
	0x00000010, 0x000000ff, 0x000000f3, 0x000000d2,
	0x000000cd, 0x0000000c, 0x00000013, 0x000000ec,
	0x0000005f, 0x00000097, 0x00000044, 0x00000017,
	0x000000c4, 0x000000a7, 0x0000007e, 0x0000003d,
	0x00000064, 0x0000005d, 0x00000019, 0x00000073,
	0x00000060, 0x00000081, 0x0000004f, 0x000000dc,
	0x00000022, 0x0000002a, 0x00000090, 0x00000088,
	0x00000046, 0x000000ee, 0x000000b8, 0x00000014,
	0x000000de, 0x0000005e, 0x0000000b, 0x000000db,
	0x000000e0, 0x00000032, 0x0000003a, 0x0000000a,
	0x00000049, 0x00000006, 0x00000024, 0x0000005c,
	0x000000c2, 0x000000d3, 0x000000ac, 0x00000062,
	0x00000091, 0x00000095, 0x000000e4, 0x00000079,
	0x000000e7, 0x000000c8, 0x00000037, 0x0000006d,
	0x0000008d, 0x000000d5, 0x0000004e, 0x000000a9,
	0x0000006c, 0x00000056, 0x000000f4, 0x000000ea,
	0x00000065, 0x0000007a, 0x000000ae, 0x00000008,
	0x000000ba, 0x00000078, 0x00000025, 0x0000002e,
	0x0000001c, 0x000000a6, 0x000000b4, 0x000000c6,
	0x000000e8, 0x000000dd, 0x00000074, 0x0000001f,
	0x0000004b, 0x000000bd, 0x0000008b, 0x0000008a,
	0x00000070, 0x0000003e, 0x000000b5, 0x00000066,
	0x00000048, 0x00000003, 0x000000f6, 0x0000000e,
	0x00000061, 0x00000035, 0x00000057, 0x000000b9,
	0x00000086, 0x000000c1, 0x0000001d, 0x0000009e,
	0x000000e1, 0x000000f8, 0x00000098, 0x00000011,
	0x00000069, 0x000000d9, 0x0000008e, 0x00000094,
	0x0000009b, 0x0000001e, 0x00000087, 0x000000e9,
	0x000000ce, 0x00000055, 0x00000028, 0x000000df,
	0x0000008c, 0x000000a1, 0x00000089, 0x0000000d,
	0x000000bf, 0x000000e6, 0x00000042, 0x00000068,
	0x00000041, 0x00000099, 0x0000002d, 0x0000000f,
	0x000000b0, 0x00000054, 0x000000bb, 0x00000016,
};

static inline uint32_t Sbox(uint32_t x, uint32_t y)
{
	/* little endian */
	/* 0: 0,0,0,63 */
	/* 1: 0,0,63,0 */
	/* 2: 0,63,0,0 */
	/* 3: 63,0,0,0 */
	const uint32_t offset = x + 1;
	const uint32_t *sbox = (const uint32_t *)&((const uint8_t *)sboxtable)[offset];
	return sbox[y];
}

const uint64_t aes_E64[256] = {
	0x006363c6a56363c6ULL, 0x007c7cf8847c7cf8ULL, 0x007777ee997777eeULL,
	0x007b7bf68d7b7bf6ULL, 0x00f2f2ff0df2f2ffULL, 0x006b6bd6bd6b6bd6ULL,
	0x006f6fdeb16f6fdeULL, 0x00c5c59154c5c591ULL, 0x0030306050303060ULL,
	0x0001010203010102ULL, 0x006767cea96767ceULL, 0x002b2b567d2b2b56ULL,
	0x00fefee719fefee7ULL, 0x00d7d7b562d7d7b5ULL, 0x00abab4de6abab4dULL,
	0x007676ec9a7676ecULL, 0x00caca8f45caca8fULL, 0x0082821f9d82821fULL,
	0x00c9c98940c9c989ULL, 0x007d7dfa877d7dfaULL, 0x00fafaef15fafaefULL,
	0x005959b2eb5959b2ULL, 0x0047478ec947478eULL, 0x00f0f0fb0bf0f0fbULL,
	0x00adad41ecadad41ULL, 0x00d4d4b367d4d4b3ULL, 0x00a2a25ffda2a25fULL,
	0x00afaf45eaafaf45ULL, 0x009c9c23bf9c9c23ULL, 0x00a4a453f7a4a453ULL,
	0x007272e4967272e4ULL, 0x00c0c09b5bc0c09bULL, 0x00b7b775c2b7b775ULL,
	0x00fdfde11cfdfde1ULL, 0x0093933dae93933dULL, 0x0026264c6a26264cULL,
	0x0036366c5a36366cULL, 0x003f3f7e413f3f7eULL, 0x00f7f7f502f7f7f5ULL,
	0x00cccc834fcccc83ULL, 0x003434685c343468ULL, 0x00a5a551f4a5a551ULL,
	0x00e5e5d134e5e5d1ULL, 0x00f1f1f908f1f1f9ULL, 0x007171e2937171e2ULL,
	0x00d8d8ab73d8d8abULL, 0x0031316253313162ULL, 0x0015152a3f15152aULL,
	0x000404080c040408ULL, 0x00c7c79552c7c795ULL, 0x0023234665232346ULL,
	0x00c3c39d5ec3c39dULL, 0x0018183028181830ULL, 0x00969637a1969637ULL,
	0x0005050a0f05050aULL, 0x009a9a2fb59a9a2fULL, 0x0007070e0907070eULL,
	0x0012122436121224ULL, 0x0080801b9b80801bULL, 0x00e2e2df3de2e2dfULL,
	0x00ebebcd26ebebcdULL, 0x0027274e6927274eULL, 0x00b2b27fcdb2b27fULL,
	0x007575ea9f7575eaULL, 0x000909121b090912ULL, 0x0083831d9e83831dULL,
	0x002c2c58742c2c58ULL, 0x001a1a342e1a1a34ULL, 0x001b1b362d1b1b36ULL,
	0x006e6edcb26e6edcULL, 0x005a5ab4ee5a5ab4ULL, 0x00a0a05bfba0a05bULL,
	0x005252a4f65252a4ULL, 0x003b3b764d3b3b76ULL, 0x00d6d6b761d6d6b7ULL,
	0x00b3b37dceb3b37dULL, 0x002929527b292952ULL, 0x00e3e3dd3ee3e3ddULL,
	0x002f2f5e712f2f5eULL, 0x0084841397848413ULL, 0x005353a6f55353a6ULL,
	0x00d1d1b968d1d1b9ULL, 0x0000000000000000ULL, 0x00ededc12cededc1ULL,
	0x0020204060202040ULL, 0x00fcfce31ffcfce3ULL, 0x00b1b179c8b1b179ULL,
	0x005b5bb6ed5b5bb6ULL, 0x006a6ad4be6a6ad4ULL, 0x00cbcb8d46cbcb8dULL,
	0x00bebe67d9bebe67ULL, 0x003939724b393972ULL, 0x004a4a94de4a4a94ULL,
	0x004c4c98d44c4c98ULL, 0x005858b0e85858b0ULL, 0x00cfcf854acfcf85ULL,
	0x00d0d0bb6bd0d0bbULL, 0x00efefc52aefefc5ULL, 0x00aaaa4fe5aaaa4fULL,
	0x00fbfbed16fbfbedULL, 0x00434386c5434386ULL, 0x004d4d9ad74d4d9aULL,
	0x0033336655333366ULL, 0x0085851194858511ULL, 0x0045458acf45458aULL,
	0x00f9f9e910f9f9e9ULL, 0x0002020406020204ULL, 0x007f7ffe817f7ffeULL,
	0x005050a0f05050a0ULL, 0x003c3c78443c3c78ULL, 0x009f9f25ba9f9f25ULL,
	0x00a8a84be3a8a84bULL, 0x005151a2f35151a2ULL, 0x00a3a35dfea3a35dULL,
	0x00404080c0404080ULL, 0x008f8f058a8f8f05ULL, 0x0092923fad92923fULL,
	0x009d9d21bc9d9d21ULL, 0x0038387048383870ULL, 0x00f5f5f104f5f5f1ULL,
	0x00bcbc63dfbcbc63ULL, 0x00b6b677c1b6b677ULL, 0x00dadaaf75dadaafULL,
	0x0021214263212142ULL, 0x0010102030101020ULL, 0x00ffffe51affffe5ULL,
	0x00f3f3fd0ef3f3fdULL, 0x00d2d2bf6dd2d2bfULL, 0x00cdcd814ccdcd81ULL,
	0x000c0c18140c0c18ULL, 0x0013132635131326ULL, 0x00ececc32fececc3ULL,
	0x005f5fbee15f5fbeULL, 0x00979735a2979735ULL, 0x00444488cc444488ULL,
	0x0017172e3917172eULL, 0x00c4c49357c4c493ULL, 0x00a7a755f2a7a755ULL,
	0x007e7efc827e7efcULL, 0x003d3d7a473d3d7aULL, 0x006464c8ac6464c8ULL,
	0x005d5dbae75d5dbaULL, 0x001919322b191932ULL, 0x007373e6957373e6ULL,
	0x006060c0a06060c0ULL, 0x0081811998818119ULL, 0x004f4f9ed14f4f9eULL,
	0x00dcdca37fdcdca3ULL, 0x0022224466222244ULL, 0x002a2a547e2a2a54ULL,
	0x0090903bab90903bULL, 0x0088880b8388880bULL, 0x0046468cca46468cULL,
	0x00eeeec729eeeec7ULL, 0x00b8b86bd3b8b86bULL, 0x001414283c141428ULL,
	0x00dedea779dedea7ULL, 0x005e5ebce25e5ebcULL, 0x000b0b161d0b0b16ULL,
	0x00dbdbad76dbdbadULL, 0x00e0e0db3be0e0dbULL, 0x0032326456323264ULL,
	0x003a3a744e3a3a74ULL, 0x000a0a141e0a0a14ULL, 0x00494992db494992ULL,
	0x0006060c0a06060cULL, 0x002424486c242448ULL, 0x005c5cb8e45c5cb8ULL,
	0x00c2c29f5dc2c29fULL, 0x00d3d3bd6ed3d3bdULL, 0x00acac43efacac43ULL,
	0x006262c4a66262c4ULL, 0x00919139a8919139ULL, 0x00959531a4959531ULL,
	0x00e4e4d337e4e4d3ULL, 0x007979f28b7979f2ULL, 0x00e7e7d532e7e7d5ULL,
	0x00c8c88b43c8c88bULL, 0x0037376e5937376eULL, 0x006d6ddab76d6ddaULL,
	0x008d8d018c8d8d01ULL, 0x00d5d5b164d5d5b1ULL, 0x004e4e9cd24e4e9cULL,
	0x00a9a949e0a9a949ULL, 0x006c6cd8b46c6cd8ULL, 0x005656acfa5656acULL,
	0x00f4f4f307f4f4f3ULL, 0x00eaeacf25eaeacfULL, 0x006565caaf6565caULL,
	0x007a7af48e7a7af4ULL, 0x00aeae47e9aeae47ULL, 0x0008081018080810ULL,
	0x00baba6fd5baba6fULL, 0x007878f0887878f0ULL, 0x0025254a6f25254aULL,
	0x002e2e5c722e2e5cULL, 0x001c1c38241c1c38ULL, 0x00a6a657f1a6a657ULL,
	0x00b4b473c7b4b473ULL, 0x00c6c69751c6c697ULL, 0x00e8e8cb23e8e8cbULL,
	0x00dddda17cdddda1ULL, 0x007474e89c7474e8ULL, 0x001f1f3e211f1f3eULL,
	0x004b4b96dd4b4b96ULL, 0x00bdbd61dcbdbd61ULL, 0x008b8b0d868b8b0dULL,
	0x008a8a0f858a8a0fULL, 0x007070e0907070e0ULL, 0x003e3e7c423e3e7cULL,
	0x00b5b571c4b5b571ULL, 0x006666ccaa6666ccULL, 0x00484890d8484890ULL,
	0x0003030605030306ULL, 0x00f6f6f701f6f6f7ULL, 0x000e0e1c120e0e1cULL,
	0x006161c2a36161c2ULL, 0x0035356a5f35356aULL, 0x005757aef95757aeULL,
	0x00b9b969d0b9b969ULL, 0x0086861791868617ULL, 0x00c1c19958c1c199ULL,
	0x001d1d3a271d1d3aULL, 0x009e9e27b99e9e27ULL, 0x00e1e1d938e1e1d9ULL,
	0x00f8f8eb13f8f8ebULL, 0x0098982bb398982bULL, 0x0011112233111122ULL,
	0x006969d2bb6969d2ULL, 0x00d9d9a970d9d9a9ULL, 0x008e8e07898e8e07ULL,
	0x00949433a7949433ULL, 0x009b9b2db69b9b2dULL, 0x001e1e3c221e1e3cULL,
	0x0087871592878715ULL, 0x00e9e9c920e9e9c9ULL, 0x00cece8749cece87ULL,
	0x005555aaff5555aaULL, 0x0028285078282850ULL, 0x00dfdfa57adfdfa5ULL,
	0x008c8c038f8c8c03ULL, 0x00a1a159f8a1a159ULL, 0x0089890980898909ULL,
	0x000d0d1a170d0d1aULL, 0x00bfbf65dabfbf65ULL, 0x00e6e6d731e6e6d7ULL,
	0x00424284c6424284ULL, 0x006868d0b86868d0ULL, 0x00414182c3414182ULL,
	0x00999929b0999929ULL, 0x002d2d5a772d2d5aULL, 0x000f0f1e110f0f1eULL,
	0x00b0b07bcbb0b07bULL, 0x005454a8fc5454a8ULL, 0x00bbbb6dd6bbbb6dULL,
	0x0016162c3a16162cULL,
};

static inline uint32_t E(uint32_t x, uint32_t y)
{
	/* little endian */
	const uint64_t *e = (const uint64_t *)((const uint8_t*)aes_E64 + (4 - x) % 4);
	return *(uint32_t*)&e[y];
}

static inline unsigned char mulby2(unsigned char x)
{
	signed char sx = x;

	return (x << 1) ^ ((unsigned char)(sx >> 8) & 0x1B);
}

/*
 * Set up an aesctx. `keylen' is measured in bytes; each can be either
 * 16 (128-bit), 24 (192-bit), or 32 * (256-bit).
 */
static void aes_setup(struct aes_ctx * ctx, const uint8_t *key, int __keylen)
{
	unsigned int i, j, Nk;
	unsigned char rconst;
	const unsigned int keylen = 16;

	/* Only accept keylen == 16 */
	if (__keylen != 16 /*&& keylen != 24 && keylen != 32*/)
		return;

	/*
	 * Basic parameters. Words per block, words in key, rounds.
	 */

	Nk = keylen / 4;
	ctx->Nr = 6 + Nk;

	/*
	 * Assign core-function pointers.
	 */

	/*
	 * Now do the key setup itself.
	 */
	for (i = 0; i < Nk; i++)
		ctx->keysched[i] = *(uint32_t*)(key + 4 * i);

	j = Nk;
	rconst = 1;
	for (; i < (ctx->Nr + 1) * 4; i++, j++) {
		unsigned int a, b, c, d;
		uint32_t temp = ctx->keysched[i - 1];

		if (j == Nk) {
			j = 0;
			a = (temp >> 8) & 0xFF;
			b = (temp >> 16) & 0xFF;
			c = (temp >> 24) & 0xFF;
			d = (temp >> 0) & 0xFF;
			temp = Sbox(0, d);
			temp |= Sbox(1, c);
			temp |= Sbox(2, b);
			temp |= Sbox(3, a) ^ rconst;
			rconst = mulby2(rconst);
		} else if (j == 4 && Nk > 6) {
			a = (temp >> 0) & 0xFF;
			b = (temp >> 8) & 0xFF;
			c = (temp >> 16) & 0xFF;
			d = (temp >> 24) & 0xFF;
			temp = Sbox(0, d);
			temp |= Sbox(1, c);
			temp |= Sbox(2, b);
			temp |= Sbox(3, a);
		}

		ctx->keysched[i] = ctx->keysched[i - Nk] ^ temp;
	}

/* Inverse cipher is unused since CTR-mode */
#if 0
	/*
	 * Now prepare the modified keys for the inverse cipher.
	 */
	for (i = 0; i <= ctx->Nr; i++) {
		for (j = 0; j < 4; j++) {
			unsigned int a, b, c, d;
			uint32_t temp = ctx->keysched[(ctx->Nr - i) * 4 + j];

			if (i != 0 && i != ctx->Nr) {
				/*
				 * Perform the InvMixColumn operation on i. The D
				 * tables give the result of InvMixColumn applied
				 * to Sboxinv on individual bytes, so we should
				 * compose Sbox with the D tables for this.
				 */
				a = (temp >> 0) & 0xFF;
				b = (temp >> 8) & 0xFF;
				c = (temp >> 16) & 0xFF;
				d = (temp >> 24) & 0xFF;
				temp = D(0, Sbox(3, a));
				temp ^= D(1, Sbox(3, b));
				temp ^= D(2, Sbox(3, c));
				temp ^= D(3, Sbox(3, d));
			} else
				temp = __builtin_bswap32(temp);

			ctx->invkeysched[i * 4 + j] = temp;
		}
	}
#endif
}

void aes_init(struct aes_ctx * ctx, const uint8_t *key, int keylen)
{
	aes_setup(ctx, key, keylen);
}

