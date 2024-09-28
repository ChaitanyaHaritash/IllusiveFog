#include <Windows.h>
#include <string.h>

void*
memset(void* dest, int val, size_t len);
char* strcpy(char* dest, const char* src);

size_t strlen(const char* s);
char* strcat(char* dest, const char* src);


size_t _itoa_str(int x, char *s);

void* memcpy(void* dest, const void* src, size_t len);
WCHAR* realloc_join_str(WCHAR* prev, WCHAR* join, PDWORD tsize);
int memcmp(const char* str1, const char* str2, size_t count);
char * strtok(char *s, const char *delim);

__forceinline char byteabs(char x);