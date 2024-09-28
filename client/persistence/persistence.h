#include "pellet/pellet_lib.h"


typedef enum persist_ec {
	persist_failed_change_server = -35
};
typedef struct pellet_dirs {
	char* pellet_write_loc;
	char* bin_write_loc;
}pellet_dirs, * Ppellet_dirs;
typedef enum persis_operation {
	no_operation = 0,
	install = 1,
	uninstall = 2
};
typedef enum persis_method {
	persist_no_method = 0,
	winrm = 1,
	winipt = 2
};
enum persis_operation select_operation(char* method);
enum persis_method select_methods(char* method);
Ppellet_dirs get_persist_locations(enum persis_method methods);
void free_persist_locations(Ppellet_dirs pdirs);
BOOL change_service_config();