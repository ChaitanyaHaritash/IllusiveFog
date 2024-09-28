#include "selfsocks5.h"
#include "common.h"
void append_first_null(struct thread_server_handle** thread_server, HANDLE h_handle, DWORD dwcount) {
	struct thread_server_handle* n_thread = (struct thread_server_handle*)allocheap(sizeof(struct thread_server_handle));
	struct thread_server_handle* l_thread = *thread_server;

	memcpy(&n_thread->count, &dwcount, sizeof(DWORD));
	if (*thread_server == NULL) {
		*thread_server = n_thread;
		return;
	}
	while (l_thread->Next != NULL)
		l_thread = l_thread->Next;
	l_thread->Next = n_thread;

}
void add_thread_handle(struct thread_server_handle** thread, HANDLE h_thread, DWORD dwcount) {
	struct thread_server_handle* pthread = (struct thread_server_handle*)allocheap(sizeof(struct thread_server_handle));
	memcpy(&pthread->count, &dwcount, sizeof(DWORD));
	memcpy(&pthread->hthread, &h_thread, sizeof(HANDLE));

	pthread->Next = (*thread);
	(*thread) = pthread;


}
void remove_thread_handle(struct thread_server_handle** thread, DWORD dwcount) {
	struct thread_server_handle* temp = *thread, * last;
	if (temp != NULL && temp->count == dwcount) {
		*thread = temp->Next;
		freeheap(temp);
		return;
	}
	while (temp != NULL && temp->count != dwcount) {
		last = temp;
		temp = temp->Next;
	}
	if (temp == NULL)return;
	last->Next = temp->Next;
	freeheap(temp);

}
void check_and_terminate(struct thread_server_handle* server_handles) {
	while (server_handles != NULL) {
		if (server_handles->hthread == NULL)
			return;
		if (WaitForSingleObject(server_handles->hthread, 0) == WAIT_OBJECT_0) {
			if (server_handles->count != 0) {
				remove_thread_handle(&server_handles, server_handles->count);
			}

		}
		server_handles = server_handles->Next;
	}
}
void terminate_all(struct thread_server_handle* server_handles) {
	while (server_handles != NULL) {
		WaitForSingleObject(server_handles->hthread, 60000); 
		TerminateThread(server_handles->hthread, 0);
		server_handles = server_handles->Next;
	}
}


void sockscleanup(Psocks_server_info socks_info) {
	shutdown(socks_info->dest_socks, SD_SEND);
	closesocket(socks_info->dest_socks);
	shutdown(socks_info->server_socks, SD_SEND);
	closesocket(socks_info->dest_socks);

}
void set_fw_rule(BOOL bdisable, char* fw_rule_port) {
	WCHAR* fw_rule_namew, * fw_rule_descriptionw, * fw_rule_groupw, * fw_rule_portw = NULL;
	DWORD temp = 0;
	temp = ascii2wide(fw_rule_name, NULL, temp);
	fw_rule_namew = (WCHAR*)allocheap(temp * sizeof(WCHAR) + 1);
	ascii2wide(fw_rule_name, fw_rule_namew, temp);
	temp = 0;
	temp = ascii2wide(fw_rule_description, NULL, temp);
	fw_rule_descriptionw = allocheap(temp * sizeof(WCHAR) + 1);
	ascii2wide(fw_rule_description, fw_rule_descriptionw, temp);
	temp = 0;
	temp = ascii2wide(fw_rule_group, NULL, temp);
	fw_rule_groupw = allocheap(temp * sizeof(WCHAR) + 1);
	ascii2wide(fw_rule_group, fw_rule_groupw, temp);
	temp = 0;
	temp = ascii2wide(fw_rule_port, NULL, temp);
	fw_rule_portw = allocheap(temp * sizeof(WCHAR) + 1);
	ascii2wide(fw_rule_port, fw_rule_portw, temp);

	INetFwPolicy2 * pNetPolicy;
	INetFwRule * pfwRules;
	INetFwRules * fwrules;
	VARIANT_BOOL is_added;
	WCHAR * current_image = allocheap(DEFAULT_IMAGE_SIZE * sizeof(WCHAR) + 1);
	DWORD size = DEFAULT_IMAGE_SIZE * sizeof(WCHAR);
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, current_image, &size);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		freeheap(allocheap);
		current_image = allocheap(DEFAULT_IMAGE_SIZE * 2 * sizeof(WCHAR) + 1);
		size = DEFAULT_IMAGE_SIZE * 2 * sizeof(WCHAR);
		QueryFullProcessImageNameW(GetCurrentProcess(), 0, current_image, &size);
	}
	CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	CoCreateInstance(&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2, (LPVOID*)& pNetPolicy);
	pNetPolicy->lpVtbl->get_Rules(pNetPolicy, &fwrules);
	CoCreateInstance(&CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwRule, &pfwRules);
	pfwRules->lpVtbl->put_Name(pfwRules, fw_rule_namew);
	pfwRules->lpVtbl->put_Description(pfwRules, fw_rule_descriptionw);
	pfwRules->lpVtbl->put_ApplicationName(pfwRules, current_image);
	pfwRules->lpVtbl->put_Protocol(pfwRules, NET_FW_IP_PROTOCOL_ANY);
	pfwRules->lpVtbl->put_LocalPorts(pfwRules, fw_rule_portw);
	pfwRules->lpVtbl->put_Direction(pfwRules, NET_FW_RULE_DIR_IN);
	pfwRules->lpVtbl->put_Grouping(pfwRules, fw_rule_groupw);
	pfwRules->lpVtbl->put_Profiles(pfwRules, NET_FW_PROFILE2_PRIVATE);
	pfwRules->lpVtbl->put_Action(pfwRules, NET_FW_ACTION_ALLOW);
	pfwRules->lpVtbl->put_Enabled(pfwRules, VARIANT_FALSE);
	if (bdisable == TRUE)
		fwrules->lpVtbl->Remove(fwrules, fw_rule_namew);
	else {
		fwrules->lpVtbl->Add(fwrules, pfwRules);

		pNetPolicy->lpVtbl->IsRuleGroupEnabled(pNetPolicy, NET_FW_PROFILE2_PRIVATE, fw_rule_groupw, &is_added);
		if (!is_added) {
			pNetPolicy->lpVtbl->EnableRuleGroup(pNetPolicy, NET_FW_PROFILE2_PRIVATE, fw_rule_groupw, TRUE);
		}

	}
	pfwRules->lpVtbl->Release(pfwRules);
	fwrules->lpVtbl->Release(fwrules);
	pNetPolicy->lpVtbl->Release(pNetPolicy);
	freeheap(fw_rule_namew);
	freeheap(fw_rule_descriptionw);
	freeheap(fw_rule_groupw);
	freeheap(fw_rule_portw);
	CoUninitialize();
}
LONG initialize_server(Psocks_server_info server_info, PULONG status) {
	WSADATA ws_data;
	WSAStartup(MAKEWORD(2, 2), &ws_data);


	InetPton(AF_INET, server_info->socketserver_ip, &server_info->socks_serveraddr_info.sin_addr.s_addr);
	server_info->socks_serveraddr_info.sin_family = AF_INET;
	server_info->socks_serveraddr_info.sin_port = htons(server_info->socketserver_port);

	server_info->bind_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(server_info->bind_server, SOL_SOCKET, SO_REUSEADDR, "1", 1);
	bind(server_info->bind_server, (SOCKADDR*)& server_info->socks_serveraddr_info, sizeof(struct sockaddr_in));
	listen(server_info->bind_server, SOMAXCONN);
	return 0;
}
LONG accepted_server_request(Psocks_server_info server_info, Psocks_negotitate_info srvr) {
	DWORD dwsize = sizeof(server_info->socks_serveraddr_info);
	fd_set readfds;
	FD_ZERO(&readfds);
	struct timeval  time_out;
	time_out.tv_sec = 1;
	time_out.tv_usec = 0;
	FD_SET(server_info->bind_server, &readfds);
	if (select(server_info->bind_server + 1, &readfds, NULL, NULL, &time_out)) {
		srvr->server_socks = accept(server_info->bind_server, (SOCKADDR*)& server_info->socks_serveraddr_info, &dwsize);
		if (srvr->server_socks == SOCKET_ERROR) {
			return -1;
		}
	}

}


int resolve(char* host, char* port, Psocks_negotitate_info srvr, ADDRINFOA addr) {

	/*ZeroMemory(&srvr->destaddrinfo, sizeof(struct addrinfo));
	srvr->destaddrinfo.ai_family = AF_UNSPEC;
	srvr->destaddrinfo.ai_socktype = SOCK_STREAM;
	srvr->destaddrinfo.ai_flags = AI_PASSIVE;
	return getaddrinfo(host, port, &hints, &addr);
*/
	return 0;
}
ULONG report_client_error(enum socks_client_report_error client_error, Psocks_server_info server_info) {
	char buf[10] = { 5, client_error, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
	send(server_info->server_socks, buf, 10, 0);
	return 0;
}
ULONG socks5_connect(struct sockaddr_in socket_address, int socks_address_sizes, Psocks_negotitate_info server_info) {
	if ((connect(server_info->dest_socks, (SOCKADDR*)& socket_address, socks_address_sizes)) == SOCKET_ERROR) {
		return -1;
	}
	return 0;

}

#define BUFSIZE 1024
void app_socket_pipe(int fd0, int fd1, Psocks_server_info server_info)
{
	int maxfd, ret;
	fd_set rd_set;
	size_t nread;
	char buffer_r[BUFSIZE];



	maxfd = (fd0 > fd1) ? fd0 : fd1;
	while (1) {
		FD_ZERO(&rd_set);
		FD_SET(fd0, &rd_set);
		FD_SET(fd1, &rd_set);

		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

		if (ret < 0 && WSAGetLastError() == EINTR) {
			continue;
		}

		if (FD_ISSET(fd0, &rd_set)) {
			nread = recv(fd0, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd1, buffer_r, nread, 0);
		}

		if (FD_ISSET(fd1, &rd_set)) {
			nread = recv(fd1, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd0, buffer_r, nread, 0);
		}
	}
}

ULONG socks5_server_subnegotiate(Psocks_negotitate_info server_info) {

	char server_ack[10] = { 5, 0, 0, 1 , 0,0,0,0, 0,0 };
	struct addrinfo* paddrinfoa = NULL, hints = { 0 };
	/*ADDRINFOA paddrinfoa;
	ZeroMemory(&paddrinfoa, sizeof(ADDRINFOA));*/
	ZeroMemory(server_info->chr_target_port, 100);
	ZeroMemory(server_info->ip_buffer, 250);
	ZeroMemory(server_info->buffer, 1024);
	DWORD error = 0;

	ZeroMemory(&server_info->socks_server_actions, sizeof(server_info->socks_server_actions));
	ZeroMemory(&server_info->socks_server_address_support, sizeof(server_info->socks_server_address_support));
	recv(server_info->server_socks, server_info->buffer, 20, 0);
	memcpy(&server_info->socks_server_actions, &server_info->buffer[1], 1);
	memcpy(&server_info->socks_server_address_support, &server_info->buffer[3], 1);
	ZeroMemory(&server_info->socks_response, sizeof(server_info->socks_response));

	switch (server_info->socks_server_address_support) {
	case IPV4: {
		memcpy(&server_info->socks_response.ip_type.ipv4.sin_addr.S_un.S_addr, &server_info->buffer[4], 4);
		server_info->socks_response.ip_type.ipv4.sin_family = AF_INET;
		ZeroMemory(server_info->ip_buffer, 250);
		RtlIpv4AddressToString(&server_info->socks_response.ip_type.ipv4.sin_addr, server_info->ip_buffer);
		memcpy(&server_info->socks_response.ip_type.ipv4.sin_port, &server_info->buffer[8], 2);
		server_info->destport = ntohs(server_info->socks_response.ip_type.ipv4.sin_port);
		break;
	}
	case IPV6:
	{
		break;
	}
	case DNS: {
		break;
	}
	default: {
		return -1;
	}

	}
	ZeroMemory(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	switch (server_info->socks_server_actions) {
	case CONNECT: {
		switch (server_info->socks_server_address_support) {
		case IPV4: {
			_itoa_str(server_info->destport, server_info->chr_target_port);
			getaddrinfo(server_info->ip_buffer, server_info->chr_target_port, &hints, &paddrinfoa);
			server_info->dest_socks = socket(paddrinfoa->ai_family, paddrinfoa->ai_socktype, paddrinfoa->ai_protocol);
			error = socks5_connect(server_info->socks_response.ip_type.ipv4, sizeof(server_info->socks_response.ip_type.ipv4), server_info);
			if (error != ERROR_SUCCESS) {
				report_client_error(EC_HOST_UNREACHABLE, server_info);

				return -1;

			}
			else {

				send(server_info->server_socks, server_ack, 10, 0);
				app_socket_pipe(server_info->server_socks, server_info->dest_socks, server_info);
			}
			break;
		}
		case IPV6:
			break;
		default:
			break;

		}
	}
	case BIND: {

	}
	default:
		break;
	}
	freeaddrinfo(paddrinfoa);
}
ULONG server_negotitatie(Psocks_negotitate_info server_info) {
	ZeroMemory(server_info->buffer, 1024);
	recv(server_info->server_socks, server_info->buffer, 10, 0);
	ZeroMemory(&server_info->socks_server_version_select, sizeof(server_info->socks_server_version_select));
	ZeroMemory(&server_info->server_authethicated_methods, sizeof(server_info->server_authethicated_methods));
	memcpy(&server_info->socks_server_version_select, &server_info->buffer[0], 1);
	memcpy(&server_info->server_authethicated_methods, &server_info->buffer[1], 1);
	switch (server_info->socks_server_version_select) {
	case SOCKS5: {
		ZeroMemory(server_info->buffer, 1024);
		server_info->buffer[0] = 5;
		server_info->buffer[1] = 0;
		send(server_info->server_socks, server_info->buffer, 2, 0);
		socks5_server_subnegotiate(server_info);
	}

	}
	return 0;
}





