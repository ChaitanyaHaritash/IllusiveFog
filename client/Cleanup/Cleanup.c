#include "Cleanup.h"
Pinitial_info get_init_info() {
	DWORD image_path_size = MAX_IMAGE_PATH_SIZE;
	DWORD image_name_size = MAX_IMAGE_NAME_SIZE;
	Pinitial_info pinfo = (Pinitial_info)allocheap(sizeof(initial_info));
	ZeroMemory(pinfo, sizeof(initial_info));
	pinfo->image_path = allocheap(MAX_IMAGE_PATH_SIZE + 1);
	ZeroMemory(pinfo->image_path, MAX_IMAGE_PATH_SIZE + 1);
	pinfo->image_name = allocheap(MAX_IMAGE_NAME_SIZE + 1);
	ZeroMemory(pinfo->image_name, MAX_IMAGE_NAME_SIZE + 1);
	QueryFullProcessImageNameA(GetCurrentProcess(), 0, pinfo->image_path, &image_path_size);
	GetModuleBaseNameA(GetCurrentProcess(), NULL, pinfo->image_name, image_name_size);
	return pinfo;
}
void self_del(HANDLE hreporter, DWORD dwreporter_threadid, Pinitial_info pinfo) {
	HANDLE fbc = NULL;
	char* initial_sc = (char*)"@ECHO OFF \nSETLOCAL\n";
	char* task_kill = (char*)"TASKKILL /F /IM ";
	char* DEL = (char*)"DEL ";
	char* del_self = (char*)"del %0";
	char* back = (char*)"\n";
	char* batch_sc = NULL;
	char* curr_back = (char*)"\\";
	char* temp = (char*)"temp.bat";
	char* current_dir_Temp = NULL;
	DWORD curr_dir_path_size = MAX_IMAGE_PATH_SIZE;
	DWORD total_size = 0;
	DWORD written = 0;
	char* task = allocheap(strlen(task_kill) + strlen(pinfo->image_name) + strlen(back) * sizeof(char) + 1);
	ZeroMemory(task, strlen(task_kill) + strlen(pinfo->image_name) + strlen(back) * sizeof(char) + 1);
	strcpy(task, task_kill);
	strcat(task, pinfo->image_name);
	strcat(task, back);
	char* dele = allocheap(strlen(DEL) + strlen(pinfo->image_name) + strlen(back) * sizeof(char) + 1);
	ZeroMemory(dele, strlen(DEL) + strlen(pinfo->image_name) + strlen(back) * sizeof(char) + 1);
	strcpy(dele, DEL);
	strcat(dele, pinfo->image_name);
	strcat(dele, back);

	freeheap(pinfo->image_name);
	freeheap(pinfo->image_path);
	freeheap(pinfo);

	batch_sc = allocheap(strlen(initial_sc) + strlen(task) + strlen(dele) + strlen(del_self) * sizeof(char) + 1);
	ZeroMemory(batch_sc, strlen(initial_sc) + strlen(task) + strlen(dele) + strlen(del_self) * sizeof(char) + 1);
	strcat(batch_sc, initial_sc);
	strcat(batch_sc, task);
	strcat(batch_sc, dele);
	strcat(batch_sc, del_self);

	total_size = strlen(batch_sc);


	current_dir_Temp = allocheap(MAX_IMAGE_PATH_SIZE + strlen(curr_back) + strlen(temp) + 1);
	ZeroMemory(current_dir_Temp, MAX_IMAGE_PATH_SIZE + strlen(curr_back) + strlen(temp) + 1);

	GetCurrentDirectoryA(curr_dir_path_size, current_dir_Temp);
	strcat(current_dir_Temp, curr_back);
	strcat(current_dir_Temp, temp);
	OutputDebugStringA(current_dir_Temp);
	fbc = CreateFileA(current_dir_Temp, FILE_WRITE_ACCESS, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(fbc, batch_sc, total_size, &written, NULL);
	CloseHandle(fbc);

	STARTUPINFOA startupinfo = { 0 };
	ZeroMemory(&startupinfo, sizeof(startupinfo));
	startupinfo.cb = sizeof(startupinfo);
	PROCESS_INFORMATION piinfo;
	ZeroMemory(&piinfo, sizeof(piinfo));
	CreateProcessA(current_dir_Temp, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startupinfo, &piinfo);
	freeheap(batch_sc);
	freeheap(current_dir_Temp);
	report(hreporter, dwreporter_threadid, NULL);




}