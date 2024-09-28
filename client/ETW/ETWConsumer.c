#include "ETWConsumer.h"
#define INITGUID

typedef struct etw_process_data {
	PBYTE u_data;
	WCHAR* cont_buffer;
	CHAR* ch_cont_buffer;
}etw_process_data, * Petw_process_data;
PTRACE_EVENT_INFO get_event_info(PEVENT_RECORD pevent) {
	DWORD dwsize = 0;
	PTRACE_EVENT_INFO pevent_info = NULL;
	if ((TdhGetEventInformation(pevent, 0, NULL, pevent_info, &dwsize)) == ERROR_INSUFFICIENT_BUFFER) {
		pevent_info = (PTRACE_EVENT_INFO)allocheap(dwsize + 1);
		ZeroMemory(pevent_info, dwsize + 1);
		TdhGetEventInformation(pevent, 0, NULL, pevent_info, &dwsize);
	}
	else {
		return NULL;
	}
	return pevent_info;
}

LPVOID realloc_copy_str(WCHAR* prev, WCHAR* join, PDWORD tsize) {
	*tsize += (strlenW(join) + 10) * sizeof(WCHAR) + 1;
	prev = reallocheap(prev, *tsize);
	StringCchCopyW(prev, strlenW(join) + 1, join);
	return prev;
}
DWORD get_array_size(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO ptrace_event_info, USHORT i, PUSHORT array_size) {

	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	if ((ptrace_event_info->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
	{
		DWORD Count = 0;
		DWORD j = ptrace_event_info->EventPropertyInfoArray[i].countPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(ptrace_event_info)+ptrace_event_info->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
		*array_size = (USHORT)Count;
	}
	else
	{
		*array_size = ptrace_event_info->EventPropertyInfoArray[i].count;
	}

	return status;

}
void remove_space_trails(PEVENT_MAP_INFO pmap_info) {
	DWORD len = 0;
	for (DWORD i = 0; i < pmap_info->EntryCount; i++) {

		len = (strlenW((LPWSTR)((PBYTE)pmap_info + pmap_info->MapEntryArray[i].OutputOffset)) - 1) * 2;
		*((LPWSTR)((PBYTE)pmap_info + (pmap_info->MapEntryArray[i].OutputOffset + len))) = L'\0';
	}
}
PEVENT_MAP_INFO pget_map_info(PEVENT_RECORD pEvent, LPWSTR pmapname, DWORD dsrc, PULONG status) {
	*status = -1;
	DWORD res = 0, map_size = 0;
	PEVENT_MAP_INFO pmap_info = NULL;

	res = TdhGetEventMapInformation(pEvent, pmapname, pmap_info, &map_size);
	if (res == ERROR_INSUFFICIENT_BUFFER) {
		pmap_info = (PEVENT_MAP_INFO)allocheap(map_size);
		res = TdhGetEventMapInformation(pmap_info, pmapname, pmap_info, &map_size);

	}
	if (res == ERROR_SUCCESS) {
		*status = 0;
		if (DecodingSourceXMLFile == dsrc) {
			remove_space_trails(pmap_info);
		}
	}
	else {
		if (res == ERROR_SUCCESS) {
			*status = 0;
		}
		else
			return NULL;
	}
	return pmap_info;

}
DWORD get_prop_len(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO ptrace_event_info, USHORT i, PUSHORT property_length, PULONG status) {
	DWORD dwtemp = 0;
	DWORD property_size = 0;
	PROPERTY_DATA_DESCRIPTOR pdescriptor;
	if ((ptrace_event_info->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength) {
		DWORD length = 0;
		DWORD Count = 0;
		DWORD j = ptrace_event_info->EventPropertyInfoArray[i].lengthPropertyIndex;
		ZeroMemory(&pdescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		pdescriptor.PropertyName = (ULONGLONG)((PBYTE)(ptrace_event_info)+ptrace_event_info->EventPropertyInfoArray[j].NameOffset);
		pdescriptor.ArrayIndex = ULONG_MAX;
		dwtemp = TdhGetPropertySize(pEvent, 0, NULL, 1, &pdescriptor, &property_size);
		dwtemp = TdhGetProperty(pEvent, 0, NULL, 1, &pdescriptor, property_size, (PBYTE)&length);
		*property_length = (USHORT)length;
	}
	else {
		if (ptrace_event_info->EventPropertyInfoArray[i].length > 0) {
			*property_length = ptrace_event_info->EventPropertyInfoArray[i].length;
		}
		if (TDH_INTYPE_BINARY == ptrace_event_info->EventPropertyInfoArray[i].nonStructType.InType &&
			TDH_OUTTYPE_IPV6 == ptrace_event_info->EventPropertyInfoArray[i].nonStructType.OutType) {
			*property_length = (USHORT)(sizeof(IN6_ADDR));

		}
		else if (TDH_INTYPE_UNICODESTRING == ptrace_event_info->EventPropertyInfoArray[i].nonStructType.InType &&
			TDH_INTYPE_ANSISTRING == ptrace_event_info->EventPropertyInfoArray[i].nonStructType.InType ||
			(ptrace_event_info->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct) {
			*property_length = ptrace_event_info->EventPropertyInfoArray[i].length;
		}
		else {

		}
	}



	return 0;
}


DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;


	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
	{
		DWORD Length = 0;
		DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
		*PropertyLength = (USHORT)Length;
	}
	else
	{
		if (pInfo->EventPropertyInfoArray[i].length > 0)
		{
			*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
		}
		else
		{

			if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
				TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
			{
				*PropertyLength = (USHORT)sizeof(IN6_ADDR);
			}
			else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				(pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
			{
				*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
			}
			else
			{

				status = ERROR_EVT_INVALID_EVENT_DATA;
				goto cleanup;
			}
		}
	}

cleanup:

	return status;
}

DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
	{
		DWORD Count = 0;
		DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
		*ArraySize = (USHORT)Count;
	}
	else
	{
		*ArraySize = pInfo->EventPropertyInfoArray[i].count;
	}

	return status;
}




PBYTE process_kernel_etw_trace(PEVENT_RECORD pevent, PTRACE_EVENT_INFO pinfo, DWORD ptrsize, USHORT i, PBYTE puserdata, PBYTE penduserdata, Petw_consumer_info etw_info, PDWORD total_size, HANDLE hfile) {
	TDHSTATUS status = ERROR_SUCCESS;
	DWORD property_len = 0;
	DWORD last_member = 0;
	DWORD fomatted_data_size = 0;
	LPWSTR pformatted_data = NULL;
	PEVENT_MAP_INFO pmapinfo = NULL;
	USHORT user_data_consumed = 0;
	USHORT user_data_len = 0;
	char* data1 = NULL;
	char* data2 = NULL;
	DWORD dwlen = 0;
	DWORD dwlen2 = 0;
	DWORD dwlen3 = 0;
	DWORD dwlen4 = 0;
	WCHAR* delim = "\n";
	WCHAR* delimiter = L":";
	char* chdelim = (char*)":";
	char* chdelimiter = (char*)"\n";
	char* ptr1, * ptr2 = NULL;
	char* ascii_total = NULL;
	DWORD dwasciitotal = 0;
	DWORD asciiret = 0;
	status = GetPropertyLength(pevent, pinfo, i, &property_len);
	if (status != ERROR_SUCCESS) {
		puserdata = NULL;
		return NULL;
	}
	USHORT array_size = 0;
	status = GetArraySize(pevent, pinfo, i, &array_size);
	for (USHORT k = 0; k < array_size; k++)
	{
		if ((pinfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
		{
			last_member = pinfo->EventPropertyInfoArray[i].structType.StructStartIndex +
				pinfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

			for (USHORT j = pinfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < last_member; j++)
			{

				puserdata = process_kernel_etw_trace(pevent, pinfo, ptrsize, j, puserdata, penduserdata, etw_info, total_size, etw_info->file);
				if (NULL == puserdata)
				{

					puserdata = NULL;
					goto cleanup;
				}
			}
		}
		else {
			ULONG ustat = 0;
			pget_map_info(pevent, (PWCHAR)((PBYTE)(pinfo)+pinfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset), pinfo->DecodingSource, &ustat);


			if (ERROR_SUCCESS != status)
			{
				puserdata = NULL;
				goto cleanup;
			}


			status = TdhFormatProperty(
				pinfo,
				pmapinfo,
				ptrsize,
				pinfo->EventPropertyInfoArray[i].nonStructType.InType,
				pinfo->EventPropertyInfoArray[i].nonStructType.OutType,
				property_len,
				(USHORT)(penduserdata - puserdata),
				puserdata,
				&fomatted_data_size,
				pformatted_data,
				&user_data_consumed);

			if (ERROR_INSUFFICIENT_BUFFER == status)
			{
				if (pformatted_data)
				{
					freeheap(pformatted_data);
					pformatted_data = NULL;
				}

				pformatted_data = (LPWSTR)allocheap(fomatted_data_size);
				if (pformatted_data == NULL)
				{
					status = ERROR_OUTOFMEMORY;
					puserdata = NULL;
					goto cleanup;
				}


				status = TdhFormatProperty(
					pinfo,
					pmapinfo,
					ptrsize,
					pinfo->EventPropertyInfoArray[i].nonStructType.InType,
					pinfo->EventPropertyInfoArray[i].nonStructType.OutType,
					property_len,
					(USHORT)(penduserdata - puserdata),
					puserdata,
					&fomatted_data_size,
					pformatted_data,
					&user_data_consumed);
			}

			if (ERROR_SUCCESS == status)
			{
				//clean this
				dwlen = wide2ascii((PWCHAR)((PBYTE)(pinfo)+pinfo->EventPropertyInfoArray[i].NameOffset), NULL, dwlen);
				dwlen2 = wide2ascii(delimiter, NULL, dwlen2);
				dwlen3 = wide2ascii(pformatted_data, NULL, dwlen3);
				dwlen4 = wide2ascii(delim, NULL, dwlen4);
				total_size = (dwlen + dwlen2 + dwlen3 + dwlen4) * 2 + 100;
				ascii_total = allocheap(total_size);
				ZeroMemory(ascii_total, total_size);
				ptr1 = allocheap(dwlen * 2 + 1);
				ptr2 = allocheap(dwlen3 * 2 + 1);
				ZeroMemory(ptr1, dwlen * 2 + 1);
				ZeroMemory(ptr2, dwlen3 * 2 + 1);
				dwlen = wide2ascii((PWCHAR)((PBYTE)(pinfo)+pinfo->EventPropertyInfoArray[i].NameOffset), ptr1, dwlen);
				dwlen3 = wide2ascii(pformatted_data, ptr2, dwlen3);
				strcat(ascii_total, ptr1);
				strcat(ascii_total, chdelim);
				strcat(ascii_total, ptr2);
				strcat(ascii_total, chdelimiter);
				freeheap(ptr1);
				freeheap(ptr2);
				WriteFile(hfile, ascii_total, strlen(ascii_total), &asciiret, NULL);
				freeheap(ascii_total);

				puserdata += user_data_consumed;
			}
			else
			{

				puserdata = NULL;
				goto cleanup;

			}
		}
	}

cleanup:

	if (pformatted_data)
	{
		freeheap(pformatted_data);
		pformatted_data = NULL;
	}

	if (pmapinfo)
	{
		freeheap(pmapinfo);
		pmapinfo = NULL;
	}

	return puserdata;

}
int WINAPI etw_kernel_consumer_callback(PEVENT_RECORD pevent, Petw_consumer_info etw_info) {
	DWORD dwllen = 0;
	DWORD dw_written = 0;
	if (pevent == NULL) {
		return NULL;
	}

	PTRACE_EVENT_INFO peventinfo = get_event_info(pevent);
	if (peventinfo == NULL) {
		return 0;
	}
	PBYTE pUserData = (PBYTE)pevent->UserData;
	PBYTE pEndOfUserData = (PBYTE)pevent->UserData + pevent->UserDataLength;

	DWORD ptrsize = 0;
	if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pevent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
	{
		ptrsize = 4;
	}
	else
	{
		ptrsize = 8;
	}
	DWORD total_size = 1;
	for (USHORT i = 0; i < peventinfo->TopLevelPropertyCount; i++)
	{
		pUserData = process_kernel_etw_trace(pevent, peventinfo, ptrsize, i, pUserData, pEndOfUserData, etw_info, &total_size, etw_info->file);
		if (NULL == pUserData)
		{
			goto cleanup;
		}

	}

cleanup:

	if (peventinfo)
	{
		freeheap(peventinfo);
	}

	return 0;

}