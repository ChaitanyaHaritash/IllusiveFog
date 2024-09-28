
#include "common/stringconvert.h"
#include "common/reporter.h"
typedef enum vr2_methods {
	no_job = 0,
	systeminfo = 1,
	network_info = 2
};
typedef struct arp_struct {
	HANDLE reporeter_event;
	DWORD reporter_thread;
	u_long destip;
	char ethernet[100];

}arp_struct, * Parp_struct;
typedef struct port_struct {
	HANDLE reporter_event;
	DWORD reporter_thread;
	DWORD destport;
	char* ip;
	char port[50];
}port_struct, * Pport_struct;
int vr2_report_enum_software(DWORD rep_thid, HANDLE rep_event);
enum vr2_methods select_method(char* method);
void vr2_report_directories(DWORD rep_thid, HANDLE rep_event);
void vr2_report_computerinfo(DWORD rep_thid, HANDLE rep_event);
ULONG arp_scan(char* host, DWORD subnet, HANDLE reporter_event, DWORD reporter_thread);
ULONG port_scan(char* host, DWORD reporter_thread, HANDLE reporter_event);