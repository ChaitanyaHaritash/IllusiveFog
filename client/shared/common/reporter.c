#include "reporter.h"
void report(HANDLE hreporter, DWORD reporter_threadid, char* message) {
	if (message != NULL)
		PostThreadMessageA(reporter_threadid, WM_
			
			_CALLBACK, (WPARAM)message, NULL);
	else
		PostThreadMessageA(reporter_threadid, WM_IllusiveFog_REPORT, NULL, NULL);
	WaitForSingleObject(hreporter, INFINITE);
	ResetEvent(hreporter);

}
void report_ec(DWORD ec,HANDLE hreporter,DWORD reporter_threadid) {
	char* temp = allocheap(100);
	ZeroMemory(temp, 100);
	_itoa_str(ec, temp);
	PostThreadMessage(reporter_threadid, WM_IllusiveFog_REPORT_ERROR_CODE, (WPARAM)temp, NULL);
	WaitForSingleObject(hreporter, INFINITE);
	ResetEvent(hreporter);
	freeheap(temp);
}