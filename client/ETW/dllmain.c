#include "ETW.h"



void thread2(Ptotal_params total_par) {

	subscribe_etw_trace(total_par, TRUE, total_par->subparam->kernel_etw);

}
__declspec(dllexport)void  thread(HANDLE localevent) {
	MSG msg;
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(localevent);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_
			
			
			_PLUGIN_LAUNCH) {
			/*Pplugin_param custom = (Pplugin_param)msg.lParam;*/
			Pplugin_param plugin_param = (Pplugin_param)msg.lParam;

			if ((select_methods(plugin_param->param)) == etw_query) {
				enum_etw_providers(plugin_param->reporter_threadid, plugin_param->reporter_event);
			}

			else {
				BOOL bkernel = FALSE;
				if ((select_methods(plugin_param->param)) == etw_subscribe_kernel) {

					bkernel = TRUE;
				}
				Ptotal_params total_par = allocheap(sizeof(total_params));
				ZeroMemory(total_par, sizeof(total_params));

				total_par->subparam = form_etw_sub_param(plugin_param->param, bkernel);
				total_par->consumer = get_consumer_info(plugin_param->reporter_event, plugin_param->reporter_threadid, total_par->subparam, bkernel);
				HANDLE hthread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)thread2, total_par, NULL, NULL);
				WaitForSingleObject(hthread, total_par->subparam->timer * 1000/*60000*/);

				total_par->consumer->bset = TRUE;
				WaitForSingleObject(hthread, /*total_par->subparam->timer **/ INFINITE);

				if (bkernel)
					subscribe_etw_trace(total_par, FALSE, TRUE);
				else
					subscribe_etw_trace(total_par, FALSE, FALSE);
				CloseTrace(total_par->trace_handle);
				CloseTrace(total_par->open_trace);
				free_etw_sub_params(total_par->subparam, bkernel);
				freeheap(total_par->consumer);

				freeheap(total_par);


			}

			report(plugin_param->reporter_event, plugin_param->reporter_threadid, NULL);
			ZeroMemory(&msg, sizeof(msg));
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

