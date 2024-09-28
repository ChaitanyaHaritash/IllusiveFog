#include "network/ntwrkcomms.h"
#include "VerboseRecon.h"
#include "common.h"
#define COMPUTER_NAME_SIZE 500
void perform_port_scan(Pport_struct pt_struct) {
	SOCKET socks;
	DWORD dwconn = 0;
	DWORD dwsize = 0;
	char* port_heap = NULL;
	LARGE_INTEGER response_timer1;
	LARGE_INTEGER response_timer2;
	struct sockaddr_in socks_addr;
	socks = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	socks_addr.sin_port = htons(pt_struct->destport);
	socks_addr.sin_family = AF_INET;
	socks_addr.sin_addr.s_addr = inet_addr(pt_struct->ip);

	dwconn = connect(socks, (SOCKADDR*)& socks_addr, sizeof(socks_addr));
	if (dwconn == ERROR_SUCCESS) {
		_itoa_str(pt_struct->destport, pt_struct->port);
		PostThreadMessageA(pt_struct->reporter_thread, WM_
			
			_CALLBACK, (WPARAM)pt_struct->port, NULL);
		WaitForSingleObject(pt_struct->reporter_event, INFINITE);
		ResetEvent(pt_struct->reporter_event);

		
	}
	shutdown(socks, SD_SEND);
	closesocket(socks);
	ExitThread(0);
}
void perform_arp(Parp_struct arps_struct) {
	u_long DestIp = arps_struct->destip;
	IPAddr SrcIp = 0;
	ULONG MacAddr[2];
	ULONG PhysAddrLen = 6;
	BYTE* bPhysAddr;
	DWORD dwRetVal;
	LARGE_INTEGER response_timer1;
	LARGE_INTEGER response_timer2;
	double response_time;
	memset(&MacAddr, 0xff, sizeof(MacAddr));
	PhysAddrLen = 6;
	SetThreadAffinityMask(GetCurrentThread(), 1);
	QueryPerformanceCounter((LARGE_INTEGER*)& response_timer1);
	SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
	QueryPerformanceCounter((LARGE_INTEGER*)& response_timer2);
	bPhysAddr = (BYTE*)& MacAddr;

	if (PhysAddrLen) {
		struct in_addr ip_addr;
		ip_addr.s_addr = DestIp;
		RtlEthernetAddressToStringA((const DL_EUI48*)(BYTE*)& MacAddr, (PSTR)arps_struct->ethernet);
		strcat(arps_struct->ethernet, ":");
		strcat(arps_struct->ethernet, inet_ntoa(ip_addr));
		PostThreadMessageA(arps_struct->reporter_thread, WM_IllusiveFog_CALLBACK, (WPARAM)arps_struct->ethernet, NULL);
		WaitForSingleObject(arps_struct->reporeter_event, INFINITE);
		ResetEvent(arps_struct->reporeter_event);

	}

	ExitThread(0);
}

void vr2_report_computerinfo(DWORD rep_thid, HANDLE rep_event) {
	char* cname = allocheap(COMPUTER_NAME_SIZE + 1);
	DWORD size = COMPUTER_NAME_SIZE;
	GetComputerNameA(cname, &size);
	report(rep_event, rep_thid, cname);
	freeheap(cname);

}
void vr2_report_directories(DWORD rep_thid, HANDLE rep_event) {
	char* delimiter = "\n";
	DWORD total_size = MAX_PATH + MAX_PATH + MAX_PATH + strlen(delimiter) + strlen(delimiter) + strlen(delimiter) + 1;
	char* total = allocheap(total_size + 1);
	ZeroMemory(total, total_size + 1);
	char* dir_ptr = NULL;

	dir_ptr = allocheap(MAX_PATH + 1);
	GetTempPathA(MAX_PATH, dir_ptr);
	strcat(total, dir_ptr);
	strcat(total, delimiter);
	ZeroMemory(dir_ptr, MAX_PATH);
	GetSystemDirectoryA(dir_ptr, MAX_PATH);
	strcat(total, dir_ptr);
	strcat(total, delimiter);
	ZeroMemory(dir_ptr, MAX_PATH);
	GetWindowsDirectoryA(dir_ptr, MAX_PATH);
	strcat(total, dir_ptr);
	strcat(total, delimiter);
	ZeroMemory(dir_ptr, MAX_PATH);
	//report(rep_event, rep_thid, dir_ptr);

	freeheap(total);
	freeheap(dir_ptr);

}
int vr2_report_enum_software(DWORD rep_thid, HANDLE rep_event) {
	LRESULT result = ERROR_SUCCESS;

	char* delimiter = "\n";
	char* cont_buffer = 0;
	DWORD cont_size = 0;
	char* software_enum_path = (char*)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
	HKEY open_key = NULL;
	DWORD dwtemp = 0;
	char* software_string;
	HKEY  open_sub_key = NULL;
	char* sub_key_name;
	char* sub_key_string;
	//add checks or calc using strlen() and then allocate buffer
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, software_enum_path, 0, KEY_READ, &open_key)) {
		return -1;
	}
	DWORD size = 5000;

	sub_key_name = (char*)allocheap(size);
	DWORD type = KEY_ALL_ACCESS;
	for (DWORD dw_index = 0; result == ERROR_SUCCESS; dw_index++) {
		size = 5000;
		ZeroMemory(sub_key_name, size);

		if ((result = RegEnumKeyExA(open_key, dw_index, sub_key_name, &size, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS) {

			dwtemp = 0; dwtemp = strlen(sub_key_name) + strlen(software_enum_path) + 100;
			sub_key_string = (char*)allocheap(dwtemp);
			strcpy(sub_key_string, software_enum_path);
			strcat(sub_key_string, "\\");
			strcat(sub_key_string, sub_key_name);
			if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub_key_string, 0, KEY_READ, &open_sub_key) != ERROR_SUCCESS) {
				RegCloseKey(open_sub_key);
				RegCloseKey(open_key);
			}
			size = 5000;
			software_string = (char*)allocheap(size);
			if (RegQueryValueExA(open_sub_key, "DisplayName", NULL, &type, (BYTE*)software_string, &size) == ERROR_SUCCESS) {
				cont_size += strlen(software_string) + strlen(delimiter) + 1;
				cont_buffer = reallocheap(cont_buffer, cont_size);
				strcat(cont_buffer, software_string);
				strcat(cont_buffer, delimiter);

			}
			else {

			}
			freeheap(software_string);
			freeheap(sub_key_string);
			RegCloseKey(open_sub_key);
		}

	}
	freeheap(sub_key_name);
	RegCloseKey(open_key);
	report(rep_event, rep_thid, cont_buffer);
	
	freeheap(cont_buffer);
	return 0;
}
enum vr2_methods select_method(char* method) {
	char* method_temp = NULL;
	enum vr2_methods vr2_query;
	vr2_query = no_job;
	for (int i = 0; i <= VR2_METHODS; i++) {
		method_temp = strstrA(method, methods[i]);
		if (method_temp) {
			if (i == 0) {
				vr2_query = network_info;
			}
			else if (i == 1) {
				vr2_query = systeminfo;
			}
			else
				vr2_query = no_job;

		}
	}
	return vr2_query;
}

ULONG get_ip(ULONG ip, ULONG subnet) {
	IPAddr ip_addr = 0;
	int i;
	IPAddr ip_addr2 = ntohl(ip);
	u_long mask = 1 << (32 - subnet);
	for (i = 0; i < subnet; i++) {
		ip_addr += ip_addr2 & mask;
		mask <<= 1;
	}
	return ntohl(++ip_addr);

}
ULONG port_scan(char* host, DWORD reporter_thread, HANDLE reporter_event) {
	WSADATA ws_data;
	WSAStartup(MAKEWORD(2, 2), &ws_data);
	int default_ports[100] = { 1,5,7,18,20,21,22,23,25,29,37,42,43,49,53,69,70,79,80,103,108,109,110,115,118,119,135,137,139,143,150,156,161,179,190,194,197,389,396,443,444,445,458,546,547,563,569,1080,-1,-1,-1 };
	Pport_struct pts_struct = (Pport_struct)allocheap(sizeof(port_struct) * 100);
	PHANDLE pts_handle = (PHANDLE)allocheap(sizeof(HANDLE) * 100);
	DWORD initialized_objects = 0;
	for (int i = 0; i <= 100; i++) {
		if (default_ports[i] == -1)
			break;
		pts_struct[i].destport = default_ports[i];
		pts_struct[i].ip = host;
		pts_struct[i].reporter_event = reporter_event;
		pts_struct[i].reporter_thread = reporter_thread;
		pts_handle[i] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)perform_port_scan, &pts_struct[i], NULL, NULL);
		initialized_objects++;
	}
	for (int i = 0; i <= initialized_objects; i++) {
		WaitForSingleObject(pts_handle[i], INFINITE);
	}
	freeheap(pts_struct);
	freeheap(pts_handle);
	WSACleanup();
}
ULONG arp_scan(char* host, DWORD subnet, HANDLE reporter_event, DWORD reporter_thread) {
	ULONG addr = 0;
	ULONG dest_count = 0;
	ULONG loop = 0;
	WSADATA ws_data;
	PHANDLE thread_handles = NULL;
	int i = 0;
	WSAStartup(MAKEWORD(2, 2), &ws_data);
	addr = lookup_address(host);
	dest_count = get_ip(addr, subnet);
	loop = 1 << (32 - subnet);
	Parp_struct _arp_thread = (Parp_struct)allocheap(sizeof(arp_struct) + sizeof(arp_struct) * loop);
	thread_handles = (PHANDLE)allocheap(sizeof(HANDLE) + sizeof(HANDLE) * loop);
	for (i = 0; i < loop; i++) {
		_arp_thread[i].destip = dest_count;
		_arp_thread[i].reporeter_event = reporter_event;
		_arp_thread[i].reporter_thread = reporter_thread;
		thread_handles[i] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)perform_arp, (LPVOID)& _arp_thread[i], NULL, NULL);
		Sleep(10);
		addr = ntohl(dest_count);
		dest_count = ntohl(++addr);
	}
	for (int i = 0; i < loop; i++) {
		if (thread_handles[i] != NULL) {
			WaitForSingleObject(thread_handles[i], INFINITE);
			TerminateThread(thread_handles[i], 0);
			CloseHandle(thread_handles[i]);

		}
	}
	freeheap(_arp_thread);
	freeheap(thread_handles);
	WSACleanup();

}