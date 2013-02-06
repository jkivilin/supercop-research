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

const uint32_t aes_D64[256 * 2] = {
	0x51f4a750, 0x00f4a750, 0x7e416553, 0x00416553,
	0x1a17a4c3, 0x0017a4c3, 0x3a275e96, 0x00275e96,
	0x3bab6bcb, 0x00ab6bcb, 0x1f9d45f1, 0x009d45f1,
	0xacfa58ab, 0x00fa58ab, 0x4be30393, 0x00e30393,
	0x2030fa55, 0x0030fa55, 0xad766df6, 0x00766df6,
	0x88cc7691, 0x00cc7691, 0xf5024c25, 0x00024c25,
	0x4fe5d7fc, 0x00e5d7fc, 0xc52acbd7, 0x002acbd7,
	0x26354480, 0x00354480, 0xb562a38f, 0x0062a38f,
	0xdeb15a49, 0x00b15a49, 0x25ba1b67, 0x00ba1b67,
	0x45ea0e98, 0x00ea0e98, 0x5dfec0e1, 0x00fec0e1,
	0xc32f7502, 0x002f7502, 0x814cf012, 0x004cf012,
	0x8d4697a3, 0x004697a3, 0x6bd3f9c6, 0x00d3f9c6,
	0x038f5fe7, 0x008f5fe7, 0x15929c95, 0x00929c95,
	0xbf6d7aeb, 0x006d7aeb, 0x955259da, 0x005259da,
	0xd4be832d, 0x00be832d, 0x587421d3, 0x007421d3,
	0x49e06929, 0x00e06929, 0x8ec9c844, 0x00c9c844,
	0x75c2896a, 0x00c2896a, 0xf48e7978, 0x008e7978,
	0x99583e6b, 0x00583e6b, 0x27b971dd, 0x00b971dd,
	0xbee14fb6, 0x00e14fb6, 0xf088ad17, 0x0088ad17,
	0xc920ac66, 0x0020ac66, 0x7dce3ab4, 0x00ce3ab4,
	0x63df4a18, 0x00df4a18, 0xe51a3182, 0x001a3182,
	0x97513360, 0x00513360, 0x62537f45, 0x00537f45,
	0xb16477e0, 0x006477e0, 0xbb6bae84, 0x006bae84,
	0xfe81a01c, 0x0081a01c, 0xf9082b94, 0x00082b94,
	0x70486858, 0x00486858, 0x8f45fd19, 0x0045fd19,
	0x94de6c87, 0x00de6c87, 0x527bf8b7, 0x007bf8b7,
	0xab73d323, 0x0073d323, 0x724b02e2, 0x004b02e2,
	0xe31f8f57, 0x001f8f57, 0x6655ab2a, 0x0055ab2a,
	0xb2eb2807, 0x00eb2807, 0x2fb5c203, 0x00b5c203,
	0x86c57b9a, 0x00c57b9a, 0xd33708a5, 0x003708a5,
	0x302887f2, 0x002887f2, 0x23bfa5b2, 0x00bfa5b2,
	0x02036aba, 0x00036aba, 0xed16825c, 0x0016825c,
	0x8acf1c2b, 0x00cf1c2b, 0xa779b492, 0x0079b492,
	0xf307f2f0, 0x0007f2f0, 0x4e69e2a1, 0x0069e2a1,
	0x65daf4cd, 0x00daf4cd, 0x0605bed5, 0x0005bed5,
	0xd134621f, 0x0034621f, 0xc4a6fe8a, 0x00a6fe8a,
	0x342e539d, 0x002e539d, 0xa2f355a0, 0x00f355a0,
	0x058ae132, 0x008ae132, 0xa4f6eb75, 0x00f6eb75,
	0x0b83ec39, 0x0083ec39, 0x4060efaa, 0x0060efaa,
	0x5e719f06, 0x00719f06, 0xbd6e1051, 0x006e1051,
	0x3e218af9, 0x00218af9, 0x96dd063d, 0x00dd063d,
	0xdd3e05ae, 0x003e05ae, 0x4de6bd46, 0x00e6bd46,
	0x91548db5, 0x00548db5, 0x71c45d05, 0x00c45d05,
	0x0406d46f, 0x0006d46f, 0x605015ff, 0x005015ff,
	0x1998fb24, 0x0098fb24, 0xd6bde997, 0x00bde997,
	0x894043cc, 0x004043cc, 0x67d99e77, 0x00d99e77,
	0xb0e842bd, 0x00e842bd, 0x07898b88, 0x00898b88,
	0xe7195b38, 0x00195b38, 0x79c8eedb, 0x00c8eedb,
	0xa17c0a47, 0x007c0a47, 0x7c420fe9, 0x00420fe9,
	0xf8841ec9, 0x00841ec9, 0x00000000, 0x00000000,
	0x09808683, 0x00808683, 0x322bed48, 0x002bed48,
	0x1e1170ac, 0x001170ac, 0x6c5a724e, 0x005a724e,
	0xfd0efffb, 0x000efffb, 0x0f853856, 0x00853856,
	0x3daed51e, 0x00aed51e, 0x362d3927, 0x002d3927,
	0x0a0fd964, 0x000fd964, 0x685ca621, 0x005ca621,
	0x9b5b54d1, 0x005b54d1, 0x24362e3a, 0x00362e3a,
	0x0c0a67b1, 0x000a67b1, 0x9357e70f, 0x0057e70f,
	0xb4ee96d2, 0x00ee96d2, 0x1b9b919e, 0x009b919e,
	0x80c0c54f, 0x00c0c54f, 0x61dc20a2, 0x00dc20a2,
	0x5a774b69, 0x00774b69, 0x1c121a16, 0x00121a16,
	0xe293ba0a, 0x0093ba0a, 0xc0a02ae5, 0x00a02ae5,
	0x3c22e043, 0x0022e043, 0x121b171d, 0x001b171d,
	0x0e090d0b, 0x00090d0b, 0xf28bc7ad, 0x008bc7ad,
	0x2db6a8b9, 0x00b6a8b9, 0x141ea9c8, 0x001ea9c8,
	0x57f11985, 0x00f11985, 0xaf75074c, 0x0075074c,
	0xee99ddbb, 0x0099ddbb, 0xa37f60fd, 0x007f60fd,
	0xf701269f, 0x0001269f, 0x5c72f5bc, 0x0072f5bc,
	0x44663bc5, 0x00663bc5, 0x5bfb7e34, 0x00fb7e34,
	0x8b432976, 0x00432976, 0xcb23c6dc, 0x0023c6dc,
	0xb6edfc68, 0x00edfc68, 0xb8e4f163, 0x00e4f163,
	0xd731dcca, 0x0031dcca, 0x42638510, 0x00638510,
	0x13972240, 0x00972240, 0x84c61120, 0x00c61120,
	0x854a247d, 0x004a247d, 0xd2bb3df8, 0x00bb3df8,
	0xaef93211, 0x00f93211, 0xc729a16d, 0x0029a16d,
	0x1d9e2f4b, 0x009e2f4b, 0xdcb230f3, 0x00b230f3,
	0x0d8652ec, 0x008652ec, 0x77c1e3d0, 0x00c1e3d0,
	0x2bb3166c, 0x00b3166c, 0xa970b999, 0x0070b999,
	0x119448fa, 0x009448fa, 0x47e96422, 0x00e96422,
	0xa8fc8cc4, 0x00fc8cc4, 0xa0f03f1a, 0x00f03f1a,
	0x567d2cd8, 0x007d2cd8, 0x223390ef, 0x003390ef,
	0x87494ec7, 0x00494ec7, 0xd938d1c1, 0x0038d1c1,
	0x8ccaa2fe, 0x00caa2fe, 0x98d40b36, 0x00d40b36,
	0xa6f581cf, 0x00f581cf, 0xa57ade28, 0x007ade28,
	0xdab78e26, 0x00b78e26, 0x3fadbfa4, 0x00adbfa4,
	0x2c3a9de4, 0x003a9de4, 0x5078920d, 0x0078920d,
	0x6a5fcc9b, 0x005fcc9b, 0x547e4662, 0x007e4662,
	0xf68d13c2, 0x008d13c2, 0x90d8b8e8, 0x00d8b8e8,
	0x2e39f75e, 0x0039f75e, 0x82c3aff5, 0x00c3aff5,
	0x9f5d80be, 0x005d80be, 0x69d0937c, 0x00d0937c,
	0x6fd52da9, 0x00d52da9, 0xcf2512b3, 0x002512b3,
	0xc8ac993b, 0x00ac993b, 0x10187da7, 0x00187da7,
	0xe89c636e, 0x009c636e, 0xdb3bbb7b, 0x003bbb7b,
	0xcd267809, 0x00267809, 0x6e5918f4, 0x005918f4,
	0xec9ab701, 0x009ab701, 0x834f9aa8, 0x004f9aa8,
	0xe6956e65, 0x00956e65, 0xaaffe67e, 0x00ffe67e,
	0x21bccf08, 0x00bccf08, 0xef15e8e6, 0x0015e8e6,
	0xbae79bd9, 0x00e79bd9, 0x4a6f36ce, 0x006f36ce,
	0xea9f09d4, 0x009f09d4, 0x29b07cd6, 0x00b07cd6,
	0x31a4b2af, 0x00a4b2af, 0x2a3f2331, 0x003f2331,
	0xc6a59430, 0x00a59430, 0x35a266c0, 0x00a266c0,
	0x744ebc37, 0x004ebc37, 0xfc82caa6, 0x0082caa6,
	0xe090d0b0, 0x0090d0b0, 0x33a7d815, 0x00a7d815,
	0xf104984a, 0x0004984a, 0x41ecdaf7, 0x00ecdaf7,
	0x7fcd500e, 0x00cd500e, 0x1791f62f, 0x0091f62f,
	0x764dd68d, 0x004dd68d, 0x43efb04d, 0x00efb04d,
	0xccaa4d54, 0x00aa4d54, 0xe49604df, 0x009604df,
	0x9ed1b5e3, 0x00d1b5e3, 0x4c6a881b, 0x006a881b,
	0xc12c1fb8, 0x002c1fb8, 0x4665517f, 0x0065517f,
	0x9d5eea04, 0x005eea04, 0x018c355d, 0x008c355d,
	0xfa877473, 0x00877473, 0xfb0b412e, 0x000b412e,
	0xb3671d5a, 0x00671d5a, 0x92dbd252, 0x00dbd252,
	0xe9105633, 0x00105633, 0x6dd64713, 0x00d64713,
	0x9ad7618c, 0x00d7618c, 0x37a10c7a, 0x00a10c7a,
	0x59f8148e, 0x00f8148e, 0xeb133c89, 0x00133c89,
	0xcea927ee, 0x00a927ee, 0xb761c935, 0x0061c935,
	0xe11ce5ed, 0x001ce5ed, 0x7a47b13c, 0x0047b13c,
	0x9cd2df59, 0x00d2df59, 0x55f2733f, 0x00f2733f,
	0x1814ce79, 0x0014ce79, 0x73c737bf, 0x00c737bf,
	0x53f7cdea, 0x00f7cdea, 0x5ffdaa5b, 0x00fdaa5b,
	0xdf3d6f14, 0x003d6f14, 0x7844db86, 0x0044db86,
	0xcaaff381, 0x00aff381, 0xb968c43e, 0x0068c43e,
	0x3824342c, 0x0024342c, 0xc2a3405f, 0x00a3405f,
	0x161dc372, 0x001dc372, 0xbce2250c, 0x00e2250c,
	0x283c498b, 0x003c498b, 0xff0d9541, 0x000d9541,
	0x39a80171, 0x00a80171, 0x080cb3de, 0x000cb3de,
	0xd8b4e49c, 0x00b4e49c, 0x6456c190, 0x0056c190,
	0x7bcb8461, 0x00cb8461, 0xd532b670, 0x0032b670,
	0x486c5c74, 0x006c5c74, 0xd0b85742, 0x00b85742,
};

static inline uint32_t D(uint32_t x, uint32_t y)
{
	const uint64_t *d = (const uint64_t *)((const uint8_t*)aes_D64 + x);
	return *(uint32_t*)&d[y];
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

#define ADD_ROUND_KEY_4(b,w) ( { \
		b[0] ^= *(keysched + (w)*4); \
		b[1] ^= *(keysched + (w)*4 + 1); \
		b[2] ^= *(keysched + (w)*4 + 2); \
		b[3] ^= *(keysched + (w)*4 + 3); \
	} )
#define MOVEWORD(b, n, i) ({ b[i] = n[i]; })

/*
 * Macros for the encryption routine.
 */
#define MAKEWORD(b, n, i) ( { \
		const int C1 = 1, C2 = 2, C3 = 3; \
		n[i] = E(0, (b[i] >> 0) & 0xFF) ^ \
			E(1, (b[(i+C1)&3] >> 8) & 0xFF) ^ \
			E(2, (b[(i+C2)&3] >> 16) & 0xFF) ^ \
			E(3, (b[(i+C3)&3] >> 24) & 0xFF); \
	} )
#define LASTWORD(b, n, i) ( { \
		const int C1 = 1, C2 = 2, C3 = 3; \
		n[i] = (Sbox(3, (b[i] >> 0) & 0xFF)) | \
			(Sbox(2, (b[(i+C1)&3] >> 8) & 0xFF)) | \
			(Sbox(1, (b[(i+C2)&3] >> 16) & 0xFF)) | \
			(Sbox(0, (b[(i+C3)&3] >> 24) & 0xFF)); \
	} )

#define ROUND_NOKEY(a, b) ( { \
		MAKEWORD(a, b, 0); \
		MAKEWORD(a, b, 1); \
		MAKEWORD(a, b, 2); \
		MAKEWORD(a, b, 3); \
	} )

#define ROUND(w, a, b) ( { \
		ADD_ROUND_KEY_4(a, w); \
		\
		ROUND_NOKEY(a, b); \
	} )

#define LASTROUND(w, a, b) ( { \
		\
		ADD_ROUND_KEY_4(a, w); \
		\
		LASTWORD(a, b, 0); \
		LASTWORD(a, b, 1); \
		LASTWORD(a, b, 2); \
		LASTWORD(a, b, 3); \
		\
		ADD_ROUND_KEY_4(b, w + 1); \
	} )

void aes_encrypt(struct aes_ctx *ctx, uint32_t out[4], const uint32_t in[4])
{
	const uint32_t *keysched = ctx->keysched;
	uint32_t a[4], b[4];

	a[0] = in[0];
	a[1] = in[1];
	a[2] = in[2];
	a[3] = in[3];

	ROUND(0, a, b);
	ROUND(1, b, a);
	ROUND(2, a, b);
	ROUND(3, b, a);
	ROUND(4, a, b);
	ROUND(5, b, a);
	ROUND(6, a, b);
	ROUND(7, b, a);
	ROUND(8, a, b);
	if ((ctx->Nr < 12)) {
		LASTROUND(9, b, a);
	} else if (ctx->Nr == 12) {
		ROUND(9, b, a);
		ROUND(10, a, b);
		LASTROUND(11, b, a);
	} else {
		ROUND(9, b, a);
		ROUND(10, a, b);
		ROUND(11, b, a);
		ROUND(12, a, b);
		LASTROUND(13, b, a);
	}

	out[0] = a[0];
	out[1] = a[1];
	out[2] = a[2];
	out[3] = a[3];
}

void aes_get_ctr_cache(struct aes_ctx *ctx, uint32_t ctr_cache[5], uint32_t iv[4])
{
	const uint32_t *keysched = ctx->keysched;
	const uint32_t *ctr_match = iv;
	uint32_t a[4], b[4];

	a[0] = ctr_match[0];
	a[1] = ctr_match[1];
	a[2] = ctr_match[2];
	a[3] = ctr_match[3];

	ADD_ROUND_KEY_4(a, 0);

	b[0] = E(0, a[0] & 0xFF); a[0] >>= 8;
	b[1] = E(0, a[1] & 0xFF); a[1] >>= 8;
	b[2] = E(0, a[2] & 0xFF); a[2] >>= 8;
	b[3] = E(0, a[3] & 0xFF); a[3] >>= 8;

	b[3] ^= E(1, a[0] & 0xFF); a[0] >>= 8;
	b[0] ^= E(1, a[1] & 0xFF); a[1] >>= 8;
	b[1] ^= E(1, a[2] & 0xFF); a[2] >>= 8;
	b[2] ^= E(1, a[3] & 0xFF); a[3] >>= 8;

	b[2] ^= E(2, a[0] & 0xFF); a[0] >>= 8;
	b[3] ^= E(2, a[1] & 0xFF); a[1] >>= 8;
	b[0] ^= E(2, a[2] & 0xFF); a[2] >>= 8;
	b[1] ^= E(2, a[3] & 0xFF); a[3] >>= 8;

	b[1] ^= E(3, a[0]);
	b[2] ^= E(3, a[1]);
	b[3] ^= E(3, a[2]);
	b[0] ^= 0/*E(3, a[3])*/;

	ctr_cache[4] = b[0];
	b[0] = 0;

	ADD_ROUND_KEY_4(b, 1);

	//a[0] = E(0, b[0] & 0xFF); b[0] >>= 8;
	a[1] = E(0, b[1] & 0xFF); b[1] >>= 8;
	a[2] = E(0, b[2] & 0xFF); b[2] >>= 8;
	a[3] = E(0, b[3] & 0xFF); b[3] >>= 8;

	//a[3] ^= E(1, b[0] & 0xFF); b[0] >>= 8;
	a[0] = E(1, b[1] & 0xFF); b[1] >>= 8;
	a[1] ^= E(1, b[2] & 0xFF); b[2] >>= 8;
	a[2] ^= E(1, b[3] & 0xFF); b[3] >>= 8;

	//a[2] ^= E(2, b[0] & 0xFF); b[0] >>= 8;
	a[3] ^= E(2, b[1] & 0xFF); b[1] >>= 8;
	a[0] ^= E(2, b[2] & 0xFF); b[2] >>= 8;
	a[1] ^= E(2, b[3] & 0xFF); b[3] >>= 8;

	//a[1] ^= E(3, b[0]);
	a[2] ^= E(3, b[1]);
	a[3] ^= E(3, b[2]);
	a[0] ^= E(3, b[3]);

	ADD_ROUND_KEY_4(a, 2);

	ctr_cache[0] = a[0];
	ctr_cache[1] = a[1];
	ctr_cache[2] = a[2];
	ctr_cache[3] = a[3];
}

void aes_ctr_match_encrypt(struct aes_ctx *ctx, uint32_t out[4], const uint32_t ctr_cache[5], unsigned char counter)
{
	const uint32_t *keysched = ctx->keysched;
	uint32_t a[4], b[4];
	uint32_t ctr;

	// round 0
	ctr = counter & 0xff;

	b[0] = ctr_cache[4];

	ctr ^= (keysched[3] >> 24) & 0xff;
	b[0] ^= E(3, ctr);

	// round 1
	b[0] ^= *(keysched + 4);

	a[0] = ctr_cache[0];
	a[1] = ctr_cache[1];
	a[2] = ctr_cache[2];
	a[3] = ctr_cache[3];

	a[0] ^= E(0, b[0] & 0xFF); b[0] >>= 8;
	a[3] ^= E(1, b[0] & 0xFF); b[0] >>= 8;
	a[2] ^= E(2, b[0] & 0xFF); b[0] >>= 8;
	a[1] ^= E(3, b[0] & 0xFF);

	ROUND_NOKEY(a, b);
	ROUND(3, b, a);
	ROUND(4, a, b);
	ROUND(5, b, a);
	ROUND(6, a, b);
	ROUND(7, b, a);
	ROUND(8, a, b);
	if ((ctx->Nr < 12)) {
		LASTROUND(9, b, a);
	} else if (ctx->Nr == 12) {
		ROUND(9, b, a);
		ROUND(10, a, b);
		LASTROUND(11, b, a);
	} else {
		ROUND(9, b, a);
		ROUND(10, a, b);
		ROUND(11, b, a);
		ROUND(12, a, b);
		LASTROUND(13, b, a);
	}

	out[0] = a[0];
	out[1] = a[1];
	out[2] = a[2];
	out[3] = a[3];
}
