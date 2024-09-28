#ifndef REPORTER_H
#define REPORTER_H
#include <Windows.h>
#include "customcrt/crtstring.h"

#include "allocation.h"
#define WM_

_EXIT_THREAD 1
#define WM_IllusiveFog_CONITINUE 2
#define WM_IllusiveFog_REPORT 3
#define WM_IllusiveFog_CALLBACK 4
#define WM_IllusiveFog_PLUGIN_LAUNCH 5
#define WM_IllusiveFog_PLUGIN_TERMINATE 6
#define WM_IllusiveFog_REPORT_ERROR_CODE 7
typedef struct pellet {
	char* socks_ip;
	char* dest_ip;
	DWORD sockport;
	DWORD destport;
	DWORD sockstimer;
	char* pellet_key;
	char* agent_id;
	BOOL enable_auth;
	char* auth_user_id;
	char* auth_user_pass;
	char* comm_key;
}pellet_param, * Ppellet_param;
typedef struct
{
	HANDLE reporter_event;
	char* param;
	DWORD reporter_threadid;
	DWORD threadid;
	HANDLE hevent;
	HANDLE plugin_events;
	char* comm_key;
	Ppellet_param pellet_struct;

}plugin_param, * Pplugin_param;
void report(HANDLE hreporter, DWORD reporter_threadid, char* message);
void report_ec(DWORD ec, HANDLE hreporter, DWORD reporter_threadid);
#endif