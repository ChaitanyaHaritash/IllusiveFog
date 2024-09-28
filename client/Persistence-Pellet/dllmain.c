

#include <Windows.h>

BOOL  DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		STARTUPINFOA si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi;
		ZeroMemory(&pi, sizeof(pi));

		CreateProcessA("C:\\Windows\\System32\\winrm.exe",
			NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
		CreateProcessA("C:\\Windows\\SysWOW64\\winrm.exe",
			NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
		CreateProcessA("C:\\Windows\\Sysnative\\winrm.exe",
			NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);

		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

