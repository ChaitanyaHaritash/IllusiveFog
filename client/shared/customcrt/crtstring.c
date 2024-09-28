#include "crtstring.h"
char *strstrA(const char *s, const char *sub_s)
{
	char c0, c1, c2, *tmps, *tmpsub;

	if (s == sub_s)
		return (char *)s;

	if (s == 0)
		return 0;

	if (sub_s == 0)
		return 0;

	c0 = *sub_s;
	while (c0 != 0) {

		while (*s != 0) {
			c2 = *s;
			if (c2 == c0)
				break;
			s++;
		}

		if (*s == 0)
			return 0;

		tmps = (char *)s;
		tmpsub = (char *)sub_s;
		do {
			c1 = *tmps;
			c2 = *tmpsub;
			tmps++;
			tmpsub++;
		} while ((c1 == c2) && (c2 != 0));

		if (c2 == 0)
			return (char *)s;

		s++;
	}
	return 0;
}

wchar_t *_strstr_w(const wchar_t *s, const wchar_t *sub_s)
{
	wchar_t c0, c1, c2, *tmps, *tmpsub;

	if (s == sub_s)
		return (wchar_t *)s;

	if (s == 0)
		return 0;

	if (sub_s == 0)
		return 0;

	c0 = *sub_s;
	while (c0 != 0) {

		while (*s != 0) {
			c2 = *s;
			if (c2 == c0)
				break;
			s++;
		}

		if (*s == 0)
			return 0;

		tmps = (wchar_t *)s;
		tmpsub = (wchar_t *)sub_s;
		do {
			c1 = *tmps;
			c2 = *tmpsub;
			tmps++;
			tmpsub++;
		} while ((c1 == c2) && (c2 != 0));

		if (c2 == 0)
			return (wchar_t *)s;

		s++;
	}
	return 0;
}
void*
memcpy(void* dest, const void* src, size_t len)
{
	char* d = dest;
   const char* s = src;
	while (len--)
		* d++ = *s++;
	return dest;
}
void*
memset(void* dest, int val, size_t len)
{
	unsigned char* ptr = (unsigned char*)dest;
	while (len-- > 0)
		* ptr++ = val;
	return dest;
}
int
memcmp(const char * str1, const char * str2, size_t count)
{
	register const unsigned char* s1 = (const unsigned char*)str1;
	register const unsigned char* s2 = (const unsigned char*)str2;

	while (count-- > 0)
	{
		if (*s1++ != *s2++)
			return s1[-1] < s2[-1] ? -1 : 1;
	}
	return 0;
}
size_t strlenW(const wchar_t* s)
{
	wchar_t* s0 = (wchar_t*)s;

	if (s == 0)
		return 0;

	while (*s != 0)
		s++;

	return (s - s0);
}


char* strcpy(char* dest, const char* src)
{
	char* p;

	if ((dest == 0) || (src == 0))
		return dest;

	if (dest == src)
		return dest;

	p = dest;
	while (*src != 0) {
		*p = *src;
		p++;
		src++;
	}

	*p = 0;
	return dest;
}

size_t strlen(const char* s)
{
	char* s0 = (char*)s;

	if (s == 0)
		return 0;

	while (*s != 0)
		s++;

	return (s - s0);
}

char* strcat(char* dest, const char* src)
{
	if ((dest == 0) || (src == 0))
		return dest;

	while (*dest != 0)
		dest++;

	while (*src != 0) {
		*dest = *src;
		dest++;
		src++;
	}

	*dest = 0;
	return dest;
}
wchar_t* strcatW(wchar_t* dest, const wchar_t* src)
{
	if ((dest == 0) || (src == 0))
		return dest;

	while (*dest != 0)
		dest++;

	while (*src != 0) {
		*dest = *src;
		dest++;
		src++;
	}

	*dest = 0;
	return dest;
}

WCHAR* realloc_join_str(WCHAR* prev, WCHAR* join, PDWORD tsize) {
	*tsize += (strlenW(join) + 10) * sizeof(WCHAR) + 1;
	prev = reallocheap(prev, *tsize);
	strcatW(prev, join);
	return prev;
}
wchar_t* strcpyW(wchar_t* dest, const wchar_t* src)
{
	wchar_t* p;

	if ((dest == 0) || (src == 0))
		return dest;

	if (dest == src)
		return dest;

	p = dest;
	while (*src != 0) {
		*p = *src;
		p++;
		src++;
	}

	*p = 0;
	return dest;
}
size_t _itoa_str(int x, char *s)
{
	int		t;
	size_t	i, r = 1, sign;

	t = x;

	if (x < 0) {
		sign = 1;
		while (t <= -10) {
			t /= 10;
			r++;
		}
	}
	else {
		sign = 0;
		while (t >= 10) {
			t /= 10;
			r++;
		}
	}

	if (s == 0)
		return r + sign;

	if (sign) {
		*s = '-';
		s++;
	}

	for (i = r; i != 0; i--) {
		s[i - 1] = (char)byteabs(x % 10) + '0';
		x /= 10;
	}

	s[r] = (char)0;
	return r + sign;
}
__forceinline char byteabs(char x) {
	if (x < 0)
		return -x;
	return x;
}
char*
strtok_r(char* s, const char* delim, char** last)
{
	const char* spanp;
	int c, sc;
	char* tok;


	if (s == NULL && (s = *last) == NULL)
		return (NULL);

	/*
	 * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
	 */
cont:
	c = *s++;
	for (spanp = delim; (sc = *spanp++) != 0;) {
		if (c == sc)
			goto cont;
	}

	if (c == 0) {		/* no non-delimiter characters */
		*last = NULL;
		return (NULL);
	}
	tok = s - 1;

	/*
	 * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
	 * Note that delim must have one NUL; we stop if we see that, too.
	 */
	for (;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = '\0';
				*last = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}



char*
strtok(char* s, const char* delim)
{
	char* last = NULL;
	return strtok_r(s, delim, &last);

}
