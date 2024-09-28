#include <Windows.h>

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;
#define DLL_NEW_THING 5
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef BOOL(WINAPI* DllMain)(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	HANDLE std_in, std_out = NULL;
	std_out = GetStdHandle(STD_OUTPUT_HANDLE);
	std_in = GetStdHandle(STD_INPUT_HANDLE);
	if ((std_in == INVALID_HANDLE_VALUE) || (std_out == INVALID_HANDLE_VALUE))
		ExitProcess(1);
	char size[50];
	ZeroMemory(size, 50);

	DWORD dw_size = 0;
	DWORD dw_read = 0;
	while (!ReadFile(std_in, &dw_size, sizeof(DWORD), &dw_read, NULL)) {

	}

	LPVOID heap_file = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dw_size + 1);
	while (!ReadFile(std_in, heap_file, dw_size, &dw_read, NULL)) {

	}

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(PBYTE)heap_file;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)heap_file + DosHeader->e_lfanew);
	DWORD dwsize = NtHeaders->OptionalHeader.SizeOfImage;
	PBYTE pbuff = (PBYTE)VirtualAlloc(NULL, dwsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD szDelta = (DWORD)pbuff - NtHeaders->OptionalHeader.ImageBase;
	CopyMemory((LPVOID)pbuff, heap_file, NtHeaders->OptionalHeader.SizeOfHeaders);
	PIMAGE_SECTION_HEADER Section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(NtHeaders);
	for (int x = 0; x <= NtHeaders->FileHeader.NumberOfSections; x++) {
		CopyMemory((LPVOID)((DWORD)pbuff + Section[x].VirtualAddress), (LPVOID)((DWORD)heap_file + Section[x].PointerToRawData),
			Section[x].SizeOfRawData);

	}
	IMAGE_DATA_DIRECTORY relocation_dir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD reloctable = relocation_dir.VirtualAddress + (DWORD)pbuff;
	DWORD relocations = 0;
	while (relocations < relocation_dir.Size) {
		PBASE_RELOCATION_BLOCK reloc_block = (PBASE_RELOCATION_BLOCK)(reloctable + relocations);
		relocations += sizeof(BASE_RELOCATION_BLOCK);
		DWORD reloc_count = (reloc_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY reloc_entries = (PBASE_RELOCATION_ENTRY)(reloctable + relocations);
		for (DWORD dwreloc = 0; dwreloc < reloc_count; dwreloc++) {
			relocations += sizeof(BASE_RELOCATION_ENTRY);
			if (reloc_entries[dwreloc].Type == 0) {
				continue;
			}
			DWORD dwRelocRva = reloc_block->PageAddress + reloc_entries[dwreloc].Offset;
			DWORD_PTR addressToPatch = 0;
			RtlCopyMemory(&addressToPatch, (LPVOID)((DWORD)pbuff + dwRelocRva), sizeof(DWORD_PTR));
			addressToPatch += szDelta;
			memcpy((LPVOID)((DWORD)pbuff + dwRelocRva), &addressToPatch, sizeof(DWORD_PTR));



		}
	}
	HMODULE hmod = NULL;


	PIMAGE_IMPORT_DESCRIPTOR impdesc = NULL;
	IMAGE_DATA_DIRECTORY impdir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	impdesc = (PIMAGE_IMPORT_DESCRIPTOR)(impdir.VirtualAddress + (DWORD)pbuff);
	LPCSTR lib = NULL;
	while (impdesc->Name != NULL) {
		lib = (LPCSTR)impdesc->Name + (DWORD)pbuff;
		hmod = LoadLibraryA(lib);
		if (lib) {
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD)pbuff + impdesc->FirstThunk);
			while (thunk->u1.AddressOfData != NULL) {
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
					LPCSTR func = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);

					thunk->u1.Function = (DWORD)GetProcAddress(hmod, func);

				}
				else {
					PIMAGE_IMPORT_BY_NAME funname = (PIMAGE_IMPORT_BY_NAME)((DWORD)pbuff + thunk->u1.AddressOfData);

					DWORD func = (DWORD)GetProcAddress(hmod, funname->Name);
					thunk->u1.Function = func;

				}
				++thunk;
			}
		}
		impdesc++;

	}


	if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		DllMain DllEntry = (DllMain)((DWORD)pbuff + NtHeaders->OptionalHeader.AddressOfEntryPoint);
		(*DllEntry)((HINSTANCE)DllEntry, DLL_PROCESS_ATTACH, 0);

	}
	else {
		LPVOID entrypoint = (LPVOID)((DWORD)pbuff + NtHeaders->OptionalHeader.AddressOfEntryPoint);


		__asm {
			mov eax, entrypoint
			call eax
			ret


		}


	}


}