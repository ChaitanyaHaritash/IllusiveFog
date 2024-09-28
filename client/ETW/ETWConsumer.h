#define INITGUID
#include "ETW.h"

#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>
int WINAPI etw_kernel_consumer_callback(PEVENT_RECORD pevent, Petw_consumer_info etw_info);