#include "pellet/pellet_lib.h"
#include <NTSecAPI.h>

typedef struct ld_path_info {
	char* bin_name;
	char* temp_dir;
	char* fail_safe_dir;
}ld_path_info, * Pld_path_info;
typedef  struct ldr_session_list {
	PPROCESS_INFORMATION ldr_session;
	struct ldr_session_list* ptr;
}ldr_session_list, * Pldr_session_list;
typedef struct sessions_maintainance {
	Pldr_session_list ldr_head;
	Pldr_session_list ldr_first;
	Pldr_session_list ldr_temp;
	Pldr_session_list ldr_prev;
}session_maintaninance, * Psession_maintainance;
#define BIN_NAME_SIZE 10
Pld_path_info get_path_info();
ULONG create_write_proc(char* ppath, char* write_buffer, DWORD write_buffer_size, PULONG status, Psession_maintainance ldr_sess_main);
void ldr_create_list(Psession_maintainance pmain);
void ldr_path_info_free(Pld_path_info pinfo);
void ldr_terminate_list(Psession_maintainance ldr_sess_main);
