#include "ntwrkcomms.h"
ULONG get_current_host(char* current_host_buffer, PULONG status){
	*status = -1;
	ULONG dwsize = sizeof(IP_ADAPTER_INFO);
	DWORD best_interface = 0;
	IPAddr ip_addr = 0;
	PIP_ADAPTER_INFO ip_adapter_info2 = NULL;
	PIP_ADAPTER_INFO ip_adapter_info1 = (PIP_ADAPTER_INFO)allocheap(dwsize);
	ZeroMemory(ip_adapter_info1, sizeof(IP_ADAPTER_INFO));
	if ((GetAdaptersInfo(ip_adapter_info1, &dwsize)) == ERROR_BUFFER_OVERFLOW) {
		freeheap(ip_adapter_info1);
		ip_adapter_info1 = allocheap(dwsize+1);
		ZeroMemory(ip_adapter_info1, dwsize + 1);
		GetAdaptersInfo(ip_adapter_info1, &dwsize);
	}
	GetBestInterface(ip_addr, &best_interface);
	ip_adapter_info2 = ip_adapter_info1;
	while (ip_adapter_info2) {
			if (ip_adapter_info2->Index == best_interface) {
				strcpy(current_host_buffer, (char*)& ip_adapter_info2->IpAddressList.IpAddress);
				*status = 0;
				break;
			}
		
		ip_adapter_info2 = ip_adapter_info2->Next;
	}
	freeheap(ip_adapter_info1);

	return 0;
}
ULONG lookup_address(char* host) {
	return inet_addr(host);
}