
#include "VerboseRecon.h"
__declspec(dllexport)void thread(HANDLE localevent) {
	MSG msg;
	HANDLE current_process = NULL;
	enum vr_methods vrmethod = 0;
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(localevent);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_
			_PLUGIN_LAUNCH) {
			Sleep(0x800);
			Pplugin_param param = (Pplugin_param)msg.lParam;
			
			vrmethod = select_method(param->param);
			if (vrmethod == mitigs) {
				current_process = GetCurrentProcess(); //close this handle once done;
				report_dep_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_aslr_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_dyn_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_handle_check_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_syscall_disable_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_process_extension_point_disable_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_cfg_polciy(current_process, param->reporter_event, param->reporter_threadid);
				report_process_sign_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_font_policy(current_process, param->reporter_event, param->reporter_threadid);
				report_image_load_policy(current_process, param->reporter_event, param->reporter_threadid);
			}
			else {
				Pupdate_info uinfo = allocheap(sizeof(update_info));
				ZeroMemory(uinfo, sizeof(update_info));
				update_session(ssWindowsUpdate, uinfo, param->reporter_event, param->reporter_threadid
					);
				report_updates(ssWindowsUpdate, uinfo, param->reporter_event, param->reporter_threadid);
				freeheap(uinfo);

			}
			report(param->reporter_event, param->reporter_threadid, NULL);
		}
		else if (msg.message == WM_IllusiveFog_PLUGIN_TERMINATE) {

			ExitThread(0);

		}

	}
}



BOOL APIENTRY DllMain( HMODULE hModule,
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

