#include "EVTX.h"
#include "common.h"
#include <Shlwapi.h>
#include <strsafe.h>
#pragma comment(lib,"Shlwapi.lib")
enum evtx_methods get_evtx_job(char* param) {
	char* method_temp = NULL;
	enum evtx_methods evtx_job;
	evtx_job = evtx_no_job;
	for (int i = 0; i <= METHODS; i++) {
		method_temp = StrStrA(param, evtx_methods[i]);
		if (method_temp) {
			if (i == 0) {
				evtx_job = evtx_enum_channel;
			}
			else if (i == 1) {
				evtx_job = evtx_query;
			}
			else if (i == 2) {
				evtx_job = evtx_clear;
			}
			else
				evtx_job = evtx_no_job;

		}
	}
	return evtx_job;
}
enum evtxlibv3_error evtenum_channels(HANDLE reporter_thread, DWORD reporter_threadid) {
	char* total = allocheap(1);
	char* delimiter = "\n";
	DWORD total_size = 0;
	WCHAR* buff = NULL;
	ULONG buff_size, buff_needed = 0;
	EVT_HANDLE channel_enum = NULL;
	ULONG status = 0;
	channel_enum = EvtOpenChannelEnum(NULL, 0);
	char* ascii_string = NULL;
	DWORD ascii_string_len = 0;
	if (channel_enum == NULL) {
		return evtlib_failed_to_open_channel;
	}
	buff = NULL, buff_size = 0, buff_needed = 0;
	do {
		if (buff_needed > buff_size) {
			freeheap(buff);
			buff_size = buff_needed;
			buff = allocheap(buff_size * sizeof(WCHAR) + 1);
			ZeroMemory(buff, buff_size * sizeof(WCHAR) + 1);
			if (buff == NULL) {
				return evtlib_failed_to_query_evt;
				break;
			}
		}
		if (EvtNextChannelPath(channel_enum, buff_size, buff, &buff_needed) == FALSE) {
			status = GetLastError();
		}
		else {
			status = ERROR_SUCCESS;
			ascii_string_len = wide2ascii(buff, NULL, buff_needed);
			ascii_string = allocheap(ascii_string_len * sizeof(WCHAR) + 1);
			ZeroMemory(ascii_string, ascii_string_len * sizeof(WCHAR) + 1);
			wide2ascii(buff, ascii_string, ascii_string_len);
			total_size += strlen(ascii_string) + strlen(delimiter) + 1;
			total = reallocheap(total, total_size);
			strcat(total, ascii_string);
			strcat(total, delimiter);
			/*	report(reporter_thread, reporter_threadid,ascii_string);
			*/	freeheap(ascii_string);
			//report()
		}
	} while ((status == ERROR_SUCCESS) || (status == ERROR_INSUFFICIENT_BUFFER));
	report(reporter_thread, reporter_threadid, total);

	freeheap(total);
	freeheap(buff);
	EvtClose(channel_enum);
	return evtlib_s_ok;

}
Pparams get_param(char* param, enum evtx_methods evt_meth) {
	Pparams pr = allocheap(sizeof(params));
	ZeroMemory(pr, sizeof(params));
	DWORD dwlen1 = 0;
	DWORD dwlen2 = 0;
	char* delim = (char*)":";
	char* ptr1, * ptr2, * ptr3 = NULL;
	ptr1 = StrStrA(param, delim);
	ptr1 += 1;
	ptr2 = StrStrA(ptr1, delim);

	if (ptr2 == NULL) {
		pr->param1 = allocheap(strlen(ptr1) + 1);
		ZeroMemory(pr->param1, strlen(ptr1) + 1);
		strcpy(pr->param1, ptr1);
		dwlen1 = ascii2wide(pr->param1, NULL, dwlen1);
		pr->wparam1 = allocheap(dwlen1 + 100);
		ZeroMemory(pr->wparam1, dwlen1 + 1);
		ascii2wide(pr->param1, pr->wparam1, dwlen1);

	}
	else {
		pr->param1 = allocheap(strlen(ptr1) - strlen(ptr2) + 10);
		ZeroMemory(pr->param1, (strlen(ptr1) - strlen(ptr2) + 10));
		StringCchCopy(pr->param1, strlen(ptr1) - strlen(ptr2) + 1, ptr1);
		ptr2 += 1;
		pr->param2 = allocheap(strlen(ptr2) + 1);
		ZeroMemory(pr->param2, strlen(ptr2) + 1);
		strcpy(pr->param2, ptr2);
		dwlen1 = ascii2wide(pr->param1, NULL, dwlen1);
		pr->wparam1 = allocheap(dwlen1 + 100);
		ZeroMemory(pr->wparam1, dwlen1 + 1);
		dwlen2 = ascii2wide(pr->param2, NULL, dwlen2);
		pr->wparam2 = allocheap(dwlen2 + 100);
		ZeroMemory(pr->wparam2, dwlen2 + 1);
		ascii2wide(pr->param1, pr->wparam1, dwlen1);
		ascii2wide(pr->param2, pr->wparam2, dwlen2);

	}
	return pr;



}
enum evtxlibv3 query_evt(WCHAR* path, WCHAR* xpath, HANDLE reporter_event, DWORD reporter_thread_id) {
	WCHAR* buff = NULL;
	char* ascii_string = NULL;
	DWORD ascii_string_len = 1;
	ascii_string = allocheap(ascii_string_len * sizeof(WCHAR) + 1);
	ULONG buff_size = 0, buff_needed = 0, count = 0, status = 0;
	EVT_HANDLE evt, query = NULL;

	query = EvtQuery(NULL, path, xpath, EvtQueryChannelPath);

	if (query == NULL) {
		return evtlib_failed_to_query_evt;
	}
	// wait for 10 minutes
	while (EvtNext(query, 1, &evt,/*INFINITE*/ 600000, 0, &count) != FALSE) {

		do {
			if (buff_needed > buff_size) {
				freeheap(buff);
				buff_size = buff_needed;
				buff = allocheap(buff_size + 1);
				ZeroMemory(buff, buff_size + 1);
				if (buff == NULL) {
					buff_size = 0;
					return evtlib_failed_to_query_evt;
				}
			}


			if (EvtRender(NULL, evt, EvtRenderEventXml, buff_size, buff, &buff_needed, &count) != FALSE) {
				status = ERROR_SUCCESS;
			}
			else
				status = GetLastError();
		} while (status == ERROR_INSUFFICIENT_BUFFER);
		if (status == ERROR_SUCCESS) {
			//report()
			ascii_string_len += wide2ascii(buff, NULL, buff_needed);
			ascii_string = reallocheap(ascii_string, ascii_string_len * sizeof(WCHAR) + 1);
			ZeroMemory(ascii_string, ascii_string_len * sizeof(WCHAR) + 1);
			wide2ascii(buff, ascii_string, ascii_string_len);
			OutputDebugStringA(ascii_string);
			
		}
		else
		{
			//failed to render
			break;
		}
		EvtClose(evt);
	}
	report(reporter_event, reporter_thread_id, ascii_string);
	freeheap(ascii_string);
	status = GetLastError();
	if (status == ERROR_NO_MORE_ITEMS) {
		status = ERROR_SUCCESS;
	}

	EvtClose(query);
	freeheap(buff);
	return evtlib_s_ok;

}
//enum evtxlibv3 query_evt(WCHAR* path, WCHAR* xpath, HANDLE reporter_event, DWORD reporter_thread_id) {
//	WCHAR* buff = NULL;
//	char* ascii_string = NULL;
//	DWORD ascii_string_len = 0;
//
//	ULONG buff_size = 0, buff_needed = 0, count = 0, status = 0;
//	EVT_HANDLE evt, query = NULL;
//
//	query = EvtQuery(NULL, path, xpath, EvtQueryChannelPath);
//
//	if (query == NULL) {
//		return evtlib_failed_to_query_evt;
//	}
//	// wait for 10 minutes
//	while (EvtNext(query, 1, &evt,/*INFINITE*/ 600000, 0, &count) != FALSE) {
//
//		do {
//			if (buff_needed > buff_size) {
//				freeheap(buff);
//				buff_size = buff_needed;
//				buff = allocheap(buff_size + 1);
//				ZeroMemory(buff, buff_size + 1);
//				if (buff == NULL) {
//					buff_size = 0;
//					return evtlib_failed_to_query_evt;
//				}
//			}
//
//
//			if (EvtRender(NULL, evt, EvtRenderEventXml, buff_size, buff, &buff_needed, &count) != FALSE) {
//				status = ERROR_SUCCESS;
//			}
//			else
//				status = GetLastError();
//		} while (status == ERROR_INSUFFICIENT_BUFFER);
//		if (status == ERROR_SUCCESS) {
//			//report()
//			ascii_string_len = wide2ascii(buff, NULL, buff_needed);
//			ascii_string = allocheap(ascii_string_len * sizeof(WCHAR) + 1);
//			ZeroMemory(ascii_string, ascii_string_len * sizeof(WCHAR) + 1);
//			wide2ascii(buff, ascii_string, ascii_string_len);
//			OutputDebugStringA(ascii_string);
//			report(reporter_event, reporter_thread_id, ascii_string);
//			freeheap(ascii_string);
//		}
//		else
//		{
//			//failed to render
//			break;
//		}
//		EvtClose(evt);
//	}
//	status = GetLastError();
//	if (status == ERROR_NO_MORE_ITEMS) {
//		status = ERROR_SUCCESS;
//	}
//
//	EvtClose(query);
//	freeheap(buff);
//	return evtlib_s_ok;
//
//}
//enum evtxlibv3 query_evt(WCHAR* path, WCHAR* xpath, HANDLE reporter_event, DWORD reporter_thread_id) {
//	WCHAR* buff = NULL;
//	char* ascii_string = NULL;
//	DWORD ascii_string_len = 0;
//
//	ULONG buff_size = 0, buff_needed = 0, count = 0, status = 0;
//	EVT_HANDLE evt, query = NULL;
//
//	query = EvtQuery(NULL, path, xpath, EvtQueryChannelPath);
//
//	if (query == NULL) {
//		return evtlib_failed_to_query_evt;
//	}
//	// wait for 10 minutes
//	while (EvtNext(query, 1, &evt,/*INFINITE*/ 600000, 0, &count) != FALSE) {
//
//		do {
//			if (buff_needed > buff_size) {
//				freeheap(buff);
//				buff_size = buff_needed;
//				buff = allocheap(buff_size + 1);
//				ZeroMemory(buff, buff_size + 1);
//				if (buff == NULL) {
//					buff_size = 0;
//					return evtlib_failed_to_query_evt;
//				}
//			}
//
//
//			if (EvtRender(NULL, evt, EvtRenderEventXml, buff_size, buff, &buff_needed, &count) != FALSE) {
//				status = ERROR_SUCCESS;
//			}
//			else
//				status = GetLastError();
//		} while (status == ERROR_INSUFFICIENT_BUFFER);
//		if (status == ERROR_SUCCESS) {
//			//report()
//			ascii_string_len = wide2ascii(buff, NULL, buff_needed);
//			ascii_string = allocheap(ascii_string_len * sizeof(WCHAR) + 1);
//			ZeroMemory(ascii_string, ascii_string_len * sizeof(WCHAR) + 1);
//			wide2ascii(buff, ascii_string, ascii_string_len);
//			OutputDebugStringA(ascii_string);
//			report(reporter_event, reporter_thread_id, ascii_string);
//			freeheap(ascii_string);
//		}
//		else
//		{
//			//failed to render
//			break;
//		}
//		EvtClose(evt);
//	}
//	status = GetLastError();
//	if (status == ERROR_NO_MORE_ITEMS) {
//		status = ERROR_SUCCESS;
//	}
//
//	EvtClose(query);
//	freeheap(buff);
//	return evtlib_s_ok;
//
//}
enum evtxlibv3 clear_evt(wchar_t* path) {
	if (EvtClearLog(NULL, path, NULL, 0)) {
		return evtlib_s_ok;
	}
	else {
		return evtxlib_failed_to_clear;
	}

}

