#include "allocation.h"
LPVOID allocheap(DWORD size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}
void freeheap(LPVOID heap) {
	HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY, heap);
}

LPVOID reallocheap(LPVOID heap,DWORD size) {
	LPVOID he = NULL;
	he=HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, size);
	if (he == NULL)
		return allocheap(size);
	else return he;
}
