#include <Windows.h>
#include <winevt.h>
#pragma comment(lib,"Wevtapi.lib")
#include "customcrt/crtstring.h"
#include "common/stringconvert.h"
#include "common/reporter.h"
typedef enum evtxlibv3_error {
	evtlib_s_ok = 0,
	evtlib_failed_to_open_channel = -150,
	evtlib_channel_failed_query = -151,
	evtlib_failed_to_query_evt = -152,
	evtxlib_failed_to_clear = -153,
	evtxlib_no_job = -154
};
typedef struct params {
	char* param1;
	char* param2;
	WCHAR* wparam1;
	WCHAR* wparam2;
}params, * Pparams;
typedef enum evtx_methods {
	evtx_enum_channel = 0,
	evtx_query = 1,
	evtx_clear = 2,
	evtx_no_job = 3
};
enum evtx_methods get_evtx_job(char* param);
enum evtxlibv3_error evtenum_channels(HANDLE reporter_thread, DWORD reporter_threadid);
enum evtxlibv3 query_evt(WCHAR* path, WCHAR* xpath, HANDLE reporter_event, DWORD reporter_thread_id);
enum evtxlibv3 clear_evt(wchar_t* path);
Pparams get_param(char* param, enum evtx_methods evt_meth);
