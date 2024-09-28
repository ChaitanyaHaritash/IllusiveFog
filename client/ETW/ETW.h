#include "common/allocation.h"
#include "common/stringconvert.h"
#include "common/reporter.h"
#include "customcrt/crtstring.h"

#include <evntprov.h>
#include <evntcons.h>
#include <tdh.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <wchar.h>
#include <bcrypt.h>


typedef struct etw_consumer_info {
	HANDLE reporter_event;
	DWORD reporter_threadid;
	GUID prov_guid;
	BOOL bset;
	BOOL bkernel;
	HANDLE file;
	char* fppp;
}etw_consumer_info, * Petw_consumer_info;
typedef enum etw_error_code {
	etw_error_sucess = 0,
	etw_error_invalid_session_name = -1,
	etw_error_controller_trace_already_exists = 183,
	etw_error_controller_failed_enable_trace_failed = -2,
	etw_error_controller_failed_disable_trace = -3,
	etw_error_controller_failed_enable_provider = -4,
	etw_error_controller_failed_disable_provider = -5,
	etw_error_controller_failed_open_trace = -6,
	etw_error_process_failed = -7,
	etw_error_string_from_clsid_failed = -32,
	etw_error_provider_enumeration_info_realloc_failed = -33,
	etw_error_invalid_parameter = -30,
	etw_error_no_plugin_initialized = -31,
	etw_error_invalid_guid = -34,
	etw_tracing_session_access_denied = -35,
	etw_process_trace_failed = -36

};
typedef enum etw_methods {
	etw_no_action = 0,
	etw_query = 1,
	etw_subscribe = 2,
	etw_subscribe_kernel = 3
};
//0x74:{AC43300D-5FCC-4800-8E99-1BD3F85F0320}:tepp:1
typedef struct etw_sub_params {
	GUID prov_guid;
	WCHAR* session_name;
	DWORD timer;
	DWORD kernel;
	BOOL kernel_etw;
}etw_sub_params, * Petw_sub_params;
typedef struct total_params {
	Petw_sub_params subparam;
	Petw_consumer_info consumer;
	TRACEHANDLE trace_handle;
	TRACEHANDLE open_trace;
}total_params, * Ptotal_params;

int enum_etw_providers(DWORD reporter_thread, HANDLE reporter_event);
enum etw_methods select_methods(char* method);
Petw_sub_params form_etw_sub_param(char* param, BOOL bkernel);
Petw_sub_params form_etw_sub_kernel_params(char* param);
void free_etw_sub_params(Petw_sub_params psubparam, BOOL bkernel);
Petw_consumer_info get_consumer_info(HANDLE reporter_event, DWORD reporter_threadid, Petw_sub_params pparams, BOOL kernel);
ULONG subscribe_etw_trace(Ptotal_params total_par, BOOL bsub, BOOL kernel);
void etw_cleanup(Ptotal_params total_params);
int WINAPI etw_consumer_callback(PEVENT_RECORD pevent, Petw_consumer_info etw_info);
