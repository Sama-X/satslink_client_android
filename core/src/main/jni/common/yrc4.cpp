#include "yrc4.h"
#include <string.h>

#if UINT_MAX > 0xFFFFL		/* System has 32-bit ints */
	#define USE_LONG_RC4
	typedef unsigned int  rc4word;
#else
	typedef unsigned char rc4word;
#endif /* UINT_MAX > 0xFFFFL */

/* The scheduled RC4 key */
typedef struct
{
	rc4word state[256];
	rc4word x, y;
}RC4KEY ;

static void rc4ExpandKey (RC4KEY *rc4, unsigned char const *key, int keylen)
{
	int x = 0, keypos = 0;
	rc4word sx = 0, y = 0;
	rc4word *state = &rc4->state[0];

	rc4->x = rc4->y = 0;

	for (x = 0; x < 256; x++)
		state[x] = x;

	for (x = 0; x < 256; x++)
	{
		sx = state[x];
		y += sx + key[keypos];
		#ifdef USE_LONG_RC4
		y &= 0xFF;
		#endif /* USE_LONG_RC4 */
		state[x] = state[y];
		state[y] = sx;

		if (++keypos == keylen)
			keypos = 0;
	}
}

static void rc4Crypt (RC4KEY *rc4, unsigned char *data, int len)
{
	rc4word x = rc4->x, y = rc4->y;
	rc4word sx = 0, sy = 0;
	rc4word *state = &rc4->state[0];

	while (len--)
	{
		x++;
	#ifdef USE_LONG_RC4
		x &= 0xFF;
	#endif /* USE_LONG_RC4 */
		sx = state[x];
		y += sx;
	#ifdef USE_LONG_RC4
		y &= 0xFF;
	#endif /* USE_LONG_RC4 */
		sy = state[y];
		state[y] = sx;
		state[x] = sy;

	#ifdef USE_LONG_RC4
		*data++ ^= state[(unsigned char) (sx + sy)];
	#else
		*data++ ^= state[(sx+sy) & 0xFF];
	#endif /* USE_LONG_RC4 */
	}

	rc4->x = x;
	rc4->y = y;
}

void yrc4 (const unsigned char *key, int keylen, const unsigned char *src, int srclen, unsigned char *dst)
{
	RC4KEY rc4;
	memcpy (dst, src, srclen);
	rc4ExpandKey (&rc4, key, keylen);
	rc4Crypt (&rc4, dst, srclen);
}
