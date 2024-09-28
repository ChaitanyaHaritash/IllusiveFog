#include <Windows.h>
void freeheap(LPVOID heap);
LPVOID allocheap(DWORD size); 
LPVOID reallocheap(LPVOID heap, DWORD size);