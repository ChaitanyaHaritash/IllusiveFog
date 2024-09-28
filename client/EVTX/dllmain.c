// dllmain.cpp : Defines the entry point for the DLL application.
#include "EVTX.h"
__declspec(dllexport)void  thread(HANDLE localevent) {
    MSG msg;
    while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
        SetEvent(localevent);
        GetMessage(&msg, NULL, NULL, NULL);
        if (msg.message == WM_
            _PLUGIN_LAUNCH) {
            /*Pplugin_param custom = (Pplugin_param)msg.lParam;*/
            Pplugin_param plugin_param = (Pplugin_param)msg.lParam;
            enum evtx_methods evt = get_evtx_job(plugin_param->param);
            
            Pparams para = NULL;
            enum evtxlibv3_error evtlib_error = evtlib_s_ok;
            switch (evt) {
            case evtx_enum_channel:
                evtlib_error = evtenum_channels(plugin_param->reporter_event, plugin_param->reporter_threadid);

                //add error code
                break;
            case evtx_query:
                para = get_param(plugin_param->param, evt);
                //add error code
                evtlib_error = query_evt(para->wparam1, para->wparam2, plugin_param->reporter_event, plugin_param->reporter_threadid);
                freeheap(para->wparam1);
                freeheap(para->wparam2);
                freeheap(para->param1);
                freeheap(para->param2);
                freeheap(para);
                break;
            case evtx_clear:
                para = get_param(plugin_param->param, evt);
                evtlib_error = clear_evt(para->wparam1);
                //add error code
                freeheap(para->wparam1);
                freeheap(para->param1);
                freeheap(para);
                break;
            default:
                report_ec(evtxlib_no_job, plugin_param->reporter_event, plugin_param->reporter_threadid);
                break;


            }
            if (evtlib_error != evtlib_s_ok) {
                report_ec(evtlib_error, plugin_param->reporter_event, plugin_param->reporter_threadid);

            }
            report(plugin_param->reporter_event, plugin_param->reporter_threadid, NULL);
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

