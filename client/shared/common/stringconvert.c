#include "stringconvert.h"
DWORD ascii2wide(char* ascii, WCHAR* wide, DWORD len) {
	if (wide == NULL) {
		len = MultiByteToWideChar(CP_UTF8, 0, ascii, -1, NULL, 0);
		return len;

	}
	else {
		MultiByteToWideChar(CP_UTF8, 0, ascii, -1, wide, len);

	}

	return 0;
}
DWORD wide2ascii(WCHAR* wide, char* ascii, DWORD len) {
	if (ascii == NULL) {
		len = WideCharToMultiByte(CP_UTF8, 0, wide, strlenW(wide), NULL, 0, NULL, NULL);
		return len;
	}
	else {
		len = WideCharToMultiByte(CP_UTF8, 0, wide, strlenW(wide), ascii, len, NULL, NULL);

	}
	return 0;
}