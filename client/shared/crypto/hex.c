#include "hex.h"
#include "common/allocation.h"
unsigned char* hexstr_to_char(const char* hexstr)
{
	DWORD len = strlen(hexstr);
	if (len % 2 != 0)
		return NULL;
	DWORD final_len = len / 2;
	unsigned char* chrs = (unsigned char*)allocheap((final_len + 1) * sizeof(*chrs));
	for (DWORD i = 0, j = 0; j < final_len; i += 2, j++)
		chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
	chrs[final_len] = '\0';
	return chrs;
}