#include "common/reporter.h"
#include "common/stringconvert.h"
#include "customcrt/crtstring.h"
#include <Psapi.h>
#define MAX_IMAGE_PATH_SIZE 10000
#define MAX_IMAGE_NAME_SIZE 2000
typedef struct initial_info {
	char* image_path;
	char* image_name;
}initial_info, * Pinitial_info;
void self_del(HANDLE hreporter, DWORD dwreporter_threadid, Pinitial_info pinfo);
Pinitial_info get_init_info();