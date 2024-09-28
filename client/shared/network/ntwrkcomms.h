#include <WinSock2.h>
#include <NTSecAPI.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <ip2string.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ntdll.lib")

ULONG get_current_host(char* current_host_buffer, PULONG status);
ULONG lookup_address(char* host);