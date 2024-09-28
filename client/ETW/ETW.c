#include "ETWConsumer.h"
#include "common.h"
int rand() {
	DWORD dw = 0;
	BCryptGenRandom(NULL, &dw, 2, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	return dw;

}
char* randstring(size_t length) {

	static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
	char* randomString = NULL;

	if (length) {
		randomString = allocheap(sizeof(char) * (length + 1));

		if (randomString) {
			for (int n = 0; n < length; n++) {
				int key = rand() % (int)(sizeof(charset) - 1);
				randomString[n] = charset[key];
			}

			randomString[length] = '\0';
		}
	}

	return randomString;
}
static VOID WINAPI etw_callback(PEVENT_RECORD pEvent)
{

	Petw_consumer_info etw_consumer = (Petw_consumer_info)pEvent->UserContext;
	etw_kernel_consumer_callback(pEvent, etw_consumer);

	if (etw_consumer->bset == TRUE) {
		CloseHandle(etw_consumer->file);
		etw_consumer->file = CreateFile(etw_consumer->fppp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		char* alloc = NULL;
		DWORD fsize = GetFileSize(etw_consumer->file,0);
		alloc = allocheap(fsize + 1);
		ZeroMemory(alloc, fsize + 1);
		DWORD dw_read = 0;
		DWORD dw_cont = 0;
		BOOL bcontinue = TRUE;
		ReadFile(etw_consumer->file, alloc, fsize, &dw_read, NULL);
		/*while (bcontinue) {
			bcontinue = ReadFile(etw_consumer->file, alloc, fsize, &dw_read, NULL);
			if (!bcontinue)
				break;
			if (dw_read == 0)
				break;
			dw_cont += dw_read;
			report(etw_consumer->reporter_event, etw_consumer->reporter_threadid, alloc);
			ZeroMemory(alloc, fsize);
			dw_read = dw_cont;
		}*/
		report(etw_consumer->reporter_event, etw_consumer->reporter_threadid, alloc);

		freeheap(alloc);
		CloseHandle(etw_consumer->file);
		DeleteFile(etw_consumer->fppp);
		freeheap(etw_consumer->fppp);
		ExitThread(0);
	}
}
static ULONG WINAPI buffer_callback(PEVENT_TRACE_LOGFILE Buffer)
{


	return TRUE;
}
Petw_sub_params form_etw_sub_kernel_params(char* param) {
	char* delimiter = ":";
	/*
	 param = StrStrA(param, delimiter);
	param += 1;
	char *delim_set= StrStrA(param,delimiter);*/
	Petw_sub_params etw_subparam = allocheap(sizeof(etw_sub_params));
	ZeroMemory(etw_subparam, sizeof(etw_sub_params));
	/*char* delim_set = StrStrA(param, delimiter);
	delim_set += 1;
	*/char* delim = StrStrA(param, delimiter);
	delim += 1;
	char* last_delim = StrStrA(delim, delimiter);
	char* ptr1 = allocheap(strlen(delim) - strlen(last_delim) + 1);
	ZeroMemory(ptr1, strlen(delim) - strlen(last_delim) + 1);
	last_delim += 1;
	char* ptr2 = allocheap(strlen(last_delim) + 1);
	ZeroMemory(ptr2, strlen(last_delim) + 1);
	DWORD len1 = 0;
	DWORD len2 = 0;
	DWORD len3 = 0;
	StringCchLengthA(last_delim, 1000, &len1);
	StringCchLengthA(delim, 100, &len2);
	StringCchLengthA(last_delim, 100, &len3);


	StringCchCopyA(ptr1, len2 - len3, delim);
	strcpy(ptr2, last_delim);
	etw_subparam->kernel = StrToIntA(ptr1);
	etw_subparam->kernel_etw = TRUE;
	etw_subparam->timer = StrToIntA(ptr2);
	freeheap(ptr1);
	freeheap(ptr2);

	/*DWORD temp1 = strlen(param);
	DWORD str_rest = strlen(delim_set);
	char* ptr1 = allocheap(temp1-str_rest);
	char* ptr2 = allocheap(strlen(delim_set + 1)+1);
	char* session_name = StrStrA(delim_set+1, delimiter);
	session_name += 1;
	char* ptr3 = allocheap(strlen(session_name)+1);
	ZeroMemory(ptr3, strlen(session_name) + 1);
	ZeroMemory(ptr1,temp1-str_rest);
	ZeroMemory(ptr2, strlen(delim_set + 1)+1);

	StringCchCopyA(ptr1, temp1 - str_rest+10 , param);
	StringCchCopyA(ptr2,strlen(delim_set)-strlen(session_name) + 10, delim_set+1);
	StringCchCopyA(ptr3, strlen(session_name)+10, session_name);
	etw_subparam->kernel = StrToIntA(ptr1);
	etw_subparam->timer = StrToIntA(ptr2);
	DWORD dwlen = ascii2wide(session_name, NULL, dwlen);
	etw_subparam->session_name = allocheap(dwlen + 1);
	ZeroMemory(etw_subparam->session_name, dwlen + 1);
	ascii2wide(session_name, etw_subparam->session_name, dwlen);
	etw_subparam->kernel_etw = TRUE;
	freeheap(ptr1);
	freeheap(ptr2);
	freeheap(ptr3);
	*/return etw_subparam;




}
int enum_etw_providers(DWORD reporter_thread, HANDLE reporter_event) {
	DWORD enum_provs_buffer = 0;
	char* total_alloc = allocheap(1);
	char* delimiter = "\n";
	DWORD total_alloc_size = 0;
	LPWSTR guid_string = NULL;
	LPWSTR complete_String = NULL;
	char* complete_char_string = NULL;
	DWORD dw_char_str_len = 0;
	DWORD error = 0;
	DWORD wchar_str_len = sizeof(WCHAR);
	PPROVIDER_ENUMERATION_INFO provider_enumeration_info = NULL;
	PPROVIDER_ENUMERATION_INFO provider_enumeration_info_temp = NULL;
	provider_enumeration_info;
	error = TdhEnumerateProviders(provider_enumeration_info, &enum_provs_buffer);
	while (ERROR_INSUFFICIENT_BUFFER == error) {
		provider_enumeration_info_temp = (PPROVIDER_ENUMERATION_INFO)reallocheap(provider_enumeration_info, enum_provs_buffer);
		provider_enumeration_info = provider_enumeration_info_temp;
		provider_enumeration_info_temp = NULL;
		error = TdhEnumerateProviders(provider_enumeration_info, &enum_provs_buffer);
	}
	if (ERROR_SUCCESS != error)
		return -1;
	for (DWORD dwcount = 0; dwcount < provider_enumeration_info->NumberOfProviders; dwcount++) {
		complete_String = allocheap(sizeof(WCHAR));
		error = StringFromCLSID(&provider_enumeration_info->TraceProviderInfoArray[dwcount].ProviderGuid, &guid_string);
		complete_String = realloc_join_str(complete_String, guid_string, &wchar_str_len);

		complete_String = realloc_join_str(complete_String, L":", &wchar_str_len);
		complete_String = realloc_join_str(complete_String, (LPWSTR)((PBYTE)(provider_enumeration_info)+provider_enumeration_info->TraceProviderInfoArray[dwcount].ProviderNameOffset), &wchar_str_len);
		dw_char_str_len = wide2ascii(complete_String, NULL, dw_char_str_len);
		complete_char_string = allocheap(dw_char_str_len * sizeof(WCHAR) + 1);
		ZeroMemory(complete_char_string, dw_char_str_len * sizeof(WCHAR) + 1);
		wide2ascii(complete_String, complete_char_string, dw_char_str_len);
		total_alloc_size += dw_char_str_len + 100;
		total_alloc = reallocheap(total_alloc, total_alloc_size);
		strcat(total_alloc, complete_char_string);
		strcat(total_alloc, delimiter);
		CoTaskMemFree(guid_string);
		freeheap(complete_String);
		freeheap(complete_char_string);

	}
	freeheap(provider_enumeration_info);
	/*OutputDebugStringA(total_alloc);*/
	report(reporter_event, reporter_thread, total_alloc);

	freeheap(total_alloc);
	return 0;

}
enum etw_methods select_methods(char* method) {
	enum etw_methods etw_do;
	char* Delimiter = ":";
	DWORD dwlen = 0;
	for (int i = 0; i <= ETW_METHODS; i++) {
		char* temp_ptr = strstrA(method, methods[i]);
		if (temp_ptr != NULL) {
			if (i == 0) { etw_do = etw_query; break; }
			else if (i == 1) { etw_do = etw_subscribe; break; }
			else if (i == 2) { etw_do = etw_subscribe_kernel; break; }
			else { etw_do = etw_no_action; break; }
		}

	}
	return etw_do;
}

Petw_sub_params form_etw_sub_param(char* param, BOOL kernel) { //might need to work a bit on this routine
	if (kernel)
		return form_etw_sub_kernel_params(param);
	DWORD templen1 = 0;
	DWORD templen2 = 0;
	WCHAR* complete_param = NULL;
	WCHAR* param_delimiter = ":";
	WCHAR* first = NULL;
	WCHAR* second = NULL;
	WCHAR* third = NULL;
	WCHAR* temp_guid = NULL;
	WCHAR* session_name = NULL;
	WCHAR* timer = NULL;



	templen1 = ascii2wide(param, NULL, templen1);
	complete_param = allocheap(templen1 * sizeof(WCHAR) + 1);
	ZeroMemory(complete_param, templen1);
	ascii2wide(param, complete_param, templen1);
	first = StrStrW(complete_param, param_delimiter);
	first += 1;
	DWORD sz_size = strlenW(complete_param) - strlenW(first);
	WCHAR* complete_ptr = complete_param + sz_size;
	first = StrStrW(complete_ptr, param_delimiter);
	templen1 = strlenW(complete_ptr) - strlenW(first) + 1;
	temp_guid = allocheap(templen1 * sizeof(WCHAR) + 1);
	ZeroMemory(temp_guid, templen1 + 1);
	StringCchCopyW(temp_guid, templen1, complete_ptr);
	first += 1;
	second = StrStrW(first, param_delimiter);
	templen2 = strlenW(first) - strlenW(second) + 1;
	session_name = allocheap(templen2 * sizeof(WCHAR) + 1);
	ZeroMemory(session_name, templen2 * sizeof(WCHAR) + 1);
	StringCchCopyW(session_name, templen2, first);
	second += 1;
	DWORD timer_etw = StrToIntW(second);
	if (timer_etw == 0)
		timer_etw = 1;
	//session_name = allocheap()
	//ZeroMemory(complete_param, strlenW(complete_param)-strlenW(first)   * sizeof(WCHAR) );
	//templen1 = strlenW(complete_param) - strlenW(first);
	////templen1 = strlenW(first) - strlenW(complete_param)-1;
	//templen1 += 1;
	//second = StrStrW(param+templen1, param_delimiter);
	//
	//templen2 = strlenW(complete_param+templen1) -strlenW(second) - templen1;
	//second += 1;
	//temp_guid = allocheap(templen2*sizeof(WCHAR)+1);
	//ZeroMemory(temp_guid, templen2*sizeof(WCHAR) + 1);
	//StringCchCopyW(temp_guid, templen2, first);
	//third = StrStrW(second, param_delimiter);
	//if (strlenW(third) > strlenW(second))
	//	templen1 = strlenW(third) - strlenW(second);
	//else
	//	templen1 = strlenW(second)-strlenW(third); // test this out;
	//session_name = allocheap(templen1 * sizeof(WCHAR )+1);
	//ZeroMemory(session_name, templen1 * sizeof(WCHAR) + 1);
	//StringCchCopyW(session_name, templen1+1, second);
	//third += 1;
	//templen2 = strlenW(third) * sizeof(WCHAR) + 1;
	//timer = allocheap(templen2);
	//ZeroMemory(timer, templen2);
	//StringCchCopyW(timer, strlenW(third)+1, third);
	//
	Petw_sub_params etw_params = allocheap(sizeof(etw_sub_params));
	ZeroMemory(etw_params, sizeof(etw_sub_params));

	IIDFromString(temp_guid, &etw_params->prov_guid);
	etw_params->session_name = allocheap(strlenW(session_name) * sizeof(WCHAR) + 1);
	ZeroMemory(etw_params->session_name, strlenW(session_name) * sizeof(WCHAR) + 1);

	StringCchCopyW(etw_params->session_name, strlenW(session_name), session_name);
	templen2 = timer_etw;
	memcpy(&etw_params->timer, &templen2, sizeof(DWORD));

	freeheap(complete_param);
	freeheap(temp_guid);
	freeheap(session_name);
	//freeheap(session_name);
//	freeheap(timer);

	return etw_params;



}

void free_etw_sub_params(Petw_sub_params psubparam, BOOL bkernel) {
	if (!bkernel)
		freeheap(psubparam->session_name);

	freeheap(psubparam);
}
Petw_consumer_info get_consumer_info(HANDLE reporter_event, DWORD reporter_threadid, Petw_sub_params pparams) {
	Petw_consumer_info consumer_info = allocheap(sizeof(etw_consumer_info));
	ZeroMemory(consumer_info, sizeof(etw_consumer_info));
	memcpy(&consumer_info->reporter_event, &reporter_event, sizeof(HANDLE));
	memcpy(&consumer_info->reporter_threadid, &reporter_threadid, sizeof(DWORD));
	memcpy(&consumer_info->prov_guid, &pparams->prov_guid, sizeof(GUID));
	return consumer_info;
}

ULONG subscribe_etw_trace(Ptotal_params total_par, BOOL bsub, BOOL kernel) {
	TRACEHANDLE trace_handle = NULL, open_trace_handle = NULL;
	EVENT_TRACE_LOGFILEW event_trace_logfile;
	PEVENT_TRACE_PROPERTIES event_trace_properties = NULL;
	DWORD event_property_size = 0;
	Petw_sub_params  psubparams = total_par->subparam;
	Petw_consumer_info  petw_info = total_par->consumer;
	ULONG status = 0;

	if (bsub == TRUE) {
		char* temp = randstring(4); //for temporary
		petw_info->fppp = allocheap(MAX_PATH + strlen(temp) + 2);
		ZeroMemory(petw_info->fppp, MAX_PATH + strlen(temp) + 2);
		GetTempPathA(MAX_PATH, petw_info->fppp);
		strcat(petw_info->fppp, temp);
		petw_info->file = CreateFile(petw_info->fppp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (petw_info->file == INVALID_HANDLE_VALUE) {

			//report ec and abort; 
		}
		freeheap(temp);
	}
	/*
	freeheap(fp);*/

	if (kernel) {
		psubparams->session_name = KERNEL_LOGGER_NAMEW;
		psubparams->prov_guid = SystemTraceControlGuid;

		event_property_size = sizeof(EVENT_TRACE_PROPERTIES) + (strlenW(psubparams->session_name) + 1) * sizeof(wchar_t);
		event_trace_properties = allocheap(event_property_size);
		ZeroMemory(&event_trace_logfile, sizeof(EVENT_TRACE_LOGFILEW));
		ZeroMemory(event_trace_properties, event_property_size);
		event_trace_properties->Wnode.BufferSize = event_property_size;
		event_trace_properties->FlushTimer = 1;
		event_trace_properties->Wnode.Guid = SystemTraceControlGuid;
		event_trace_properties->Wnode.ClientContext = 1;
		event_trace_properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		event_trace_properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		/*	event_trace_properties->FlushTimer = 1;
			*/event_trace_properties->LogFileNameOffset = 0;
			event_trace_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

			switch (psubparams->kernel) {
			case 1:
				event_trace_properties->EnableFlags = EVENT_TRACE_FLAG_FILE_IO_INIT;
				break;
			case 2:
				event_trace_properties->EnableFlags = EVENT_TRACE_FLAG_REGISTRY;
				break;
			case 3:
				event_trace_properties->EnableFlags = EVENT_TRACE_FLAG_IMAGE_LOAD;
				break;
			case 4:
				event_trace_properties->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
				break;
			default:
				event_trace_properties->EnableFlags = EVENT_TRACE_FLAG_FILE_IO_INIT;
				break;
			}
			petw_info->bset = FALSE;
			petw_info->bkernel = TRUE;
			event_trace_logfile.LoggerName = psubparams->session_name;
			event_trace_logfile.LogFileName = NULL;
			event_trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
			event_trace_logfile.BufferCallback = &buffer_callback; //some callback
			event_trace_logfile.Context = petw_info; //pass struct 
			event_trace_logfile.EventRecordCallback = &etw_callback;
	}
	else {
		petw_info->bkernel = FALSE;
		event_property_size = sizeof(EVENT_TRACE_PROPERTIES) + (strlenW(psubparams->session_name) + 1) * sizeof(wchar_t);

		event_trace_properties = allocheap(event_property_size);

		ZeroMemory(&event_trace_logfile, sizeof(EVENT_TRACE_LOGFILEW));
		ZeroMemory(event_trace_properties, event_property_size);
		event_trace_properties->Wnode.BufferSize = event_property_size;
		event_trace_properties->Wnode.ClientContext = 1;	//use QPC for timestamp resolution
		event_trace_properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		event_trace_properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		event_trace_properties->FlushTimer = 1;
		event_trace_properties->LogFileNameOffset = 0;
		event_trace_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		GUID szguid;
		CoCreateGuid(&szguid);

		event_trace_properties->Wnode.Guid = szguid;	// We could set a random guid here, but StartTrace will create for us if not supplied
		petw_info->bset = FALSE;
		event_trace_logfile.LoggerName = psubparams->session_name;
		event_trace_logfile.LogFileName = NULL;
		event_trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
		event_trace_logfile.BufferCallback = &buffer_callback; //some callback
		event_trace_logfile.Context = petw_info; //pass struct
		event_trace_logfile.EventRecordCallback = &etw_callback;
	}

	open_trace_handle = OpenTraceW(&event_trace_logfile);
	memcpy(&total_par->open_trace, &open_trace_handle, sizeof(TRACEHANDLE));

	DWORD last_Error = GetLastError();
	if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
		freeheap(event_trace_properties);
		return -1; //freeheap and return error code
	}

	//if (kernel)
	//	return subscribe_etw_kernel_trace(event_trace_properties, event_trace_logfile, open_trace_handle, FALSE, bsub,total_par);
	if (kernel)
		status = StartTraceW(&trace_handle, KERNEL_LOGGER_NAMEW, event_trace_properties);
	else
		status = StartTraceW(&trace_handle, psubparams->session_name, event_trace_properties);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_ALREADY_EXISTS) {
			//open_trace_handle=OpenTraceW(&event_trace_logfile);
			EnableTraceEx2(trace_handle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, NULL, NULL, NULL, NULL, NULL);
			ControlTraceW(open_trace_handle, total_par->subparam->session_name, event_trace_properties, EVENT_TRACE_CONTROL_STOP);

			freeheap(event_trace_properties);
			CloseTrace(trace_handle);
			CloseTrace(open_trace_handle);

			if (bsub == FALSE) {
				return 0;
			}
			else {
				DeleteFile(petw_info->fppp);
				freeheap(petw_info->fppp);
				CloseHandle(petw_info->file);
				if (kernel)
					subscribe_etw_trace(total_par, TRUE, TRUE); //recurse
				else
					subscribe_etw_trace(total_par, TRUE, FALSE); //recurse

			}

		}


	}

	if (kernel)
		status = EnableTraceEx2(trace_handle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, NULL, NULL, 0, NULL);
	else
		status = EnableTraceEx2(trace_handle, &psubparams->prov_guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, NULL, NULL, 0, NULL);
	memcpy(&total_par->trace_handle, &trace_handle, sizeof(TRACEHANDLE));

	freeheap(event_trace_properties);

	status = ProcessTrace(&open_trace_handle, 1, NULL, NULL);
	if (!status) {
		report_ec(etw_process_trace_failed, petw_info->reporter_event, petw_info->reporter_threadid);

	}
	//CloseTrace(trace_handle);
	//CloseTrace(open_trace_handle);

}

