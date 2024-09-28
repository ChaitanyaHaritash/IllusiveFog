#include "CSocketlib.h"

void delay(DWORD socks_timer) {
	LARGE_INTEGER wait_integer;
	HANDLE waitaible_Timer = NULL;
	wait_integer.QuadPart = -100000000LL;
	waitaible_Timer = CreateWaitableTimer(NULL, NULL, NULL);
	SetWaitableTimer(waitaible_Timer, &wait_integer, 0, NULL, NULL, 0);
	WaitForSingleObject(waitaible_Timer, INFINITE);

}
enum sock_result verify_packet(char* packets, BOOL auth_enabled) {
	if (auth_enabled) {
		if (packets[1] == 2 && packets[0] == 5) {
			return sock_s_ok;
		}
	}
	if (packets[1] == 0 && packets[0] == 5) {
		return sock_s_ok;
	}
	return Error_reply_packet_verification;
}
void free_socket_address(Psocket_address sock_addr) {
	freeheap(sock_addr->destaddr);
	freeheap(sock_addr->sockaddr);
	freeheap(sock_addr);

}
Psocket_address form_socket_address(char* sockip, DWORD sockport, char* destip, DWORD destport, BOOL bauth_enable, char* socks_user_auth, char* socks_pass_auth) {
	Psocket_address sock_addr = (Psocket_address)allocheap(sizeof(socket_address));
	sock_addr->destaddr = allocheap(DESTADDRESS_SIZE + 1);
	ZeroMemory(sock_addr->destaddr, DESTADDRESS_SIZE + 1);
	strcpy(sock_addr->destaddr, destip);
	sock_addr->destport = destport;
#ifdef SOCKS
	sock_addr->sockaddr = allocheap(SOCKADDRESS_SIZE + 1);
	ZeroMemory(sock_addr->sockaddr, SOCKADDRESS_SIZE + 1);
	sock_addr->sockport = sockport;
	strcpy(sock_addr->sockaddr, sockip);
	if (bauth_enable) {
		sock_addr->auth_enable = bauth_enable;
		sock_addr->socks_user_auth = allocheap(strlen(socks_user_auth) + 1);
		ZeroMemory(sock_addr->socks_user_auth, strlen(socks_user_auth) + 1);
		sock_addr->socks_user_pass = allocheap(strlen(socks_pass_auth) + 1);
		ZeroMemory(sock_addr->socks_user_pass, strlen(socks_pass_auth) + 1);
		strcpy(sock_addr->socks_user_auth, socks_user_auth);
		strcpy(sock_addr->socks_user_pass, socks_pass_auth);
	}
#endif

	return sock_addr;


}

SOCKET socket_connect(Psocket_address socks_addr, SOCKET socket_conn, PULONG  last_error) {
#ifdef SOCKS

	if (socks_addr->sockaddr == NULL)
		return Error_nosock_ip;
	if (socks_addr->destaddr == NULL)
		return Error_nosock_ip;
	if (socks_addr->destport == 0)
		return Error_zero_port;
	if (socks_addr->sockport == 0)
		return Error_zero_port;
	struct sockaddr_in* destaddrsocks;
	char negotiation_packet[20];
	char final_negotiation_packet[20];
	char reply_packet[20];
	char final_response_packet[20];
	if (socks_addr->auth_enable) {
		negotiation_packet[0] = 5;
		negotiation_packet[1] = 2;
		negotiation_packet[2] = 0;
		negotiation_packet[3] = 2;
	}
	else {
		negotiation_packet[0] = 5;
		negotiation_packet[1] = 1;
		negotiation_packet[2] = 0;
	}
	final_negotiation_packet[0] = 5;
	final_negotiation_packet[1] = 1;
	final_negotiation_packet[2] = 0;
	final_negotiation_packet[3] = 1;
	DWORD dwnum_size = 0;
	char char_destport[100];
	char char_sockport[100];
	ZeroMemory(char_destport, 100);
	ZeroMemory(char_sockport, 100);
	struct addrinfo dest_addrhints;
	struct addrinfo sock_addrhints;
	struct addrinfo* sockpaddr = NULL;
	struct addrinfo* destpaddr = NULL;
	WSADATA ws_data;

	ZeroMemory(&dest_addrhints, sizeof(dest_addrhints));
	ZeroMemory(&sock_addrhints, sizeof(sock_addrhints));

	dwnum_size = _itoa_str(socks_addr->destport, 0);

	_itoa_str(socks_addr->destport, char_destport);

	_itoa_str(socks_addr->sockport, char_sockport);
	dest_addrhints.ai_family = AF_INET;
	dest_addrhints.ai_socktype = SOCK_STREAM;
	dest_addrhints.ai_protocol = IPPROTO_TCP;
	
	sock_addrhints.ai_family = AF_INET;
	sock_addrhints.ai_socktype = SOCK_STREAM;
	sock_addrhints.ai_protocol = IPPROTO_TCP;
	if ((WSAStartup(MAKEWORD(2, 2), &ws_data)) != NULL) {
		*last_error = Error_WSA_Socks;
		goto cleanup;
	}
	if (getaddrinfo(socks_addr->sockaddr, char_sockport, &sock_addrhints, &sockpaddr) != NULL) {

		*last_error = Error_GetAddrError;
		goto cleanup;
	}
	if (getaddrinfo(socks_addr->destaddr, char_destport, &dest_addrhints, &destpaddr) != NULL) {
		*last_error = Error_GetAddrError;
		goto cleanup;

	}
	if ((socket_conn = socket(sockpaddr->ai_family, sockpaddr->ai_socktype, sockpaddr->ai_protocol)) == -1) {
		*last_error = Error_SocksConnect;
		goto cleanup;
	}
	DWORD timer = 1000;
	setsockopt(socket_conn, SOL_SOCKET, SO_RCVTIMEO, (char*)& timer, sizeof(timer));

	if ((connect(socket_conn, sockpaddr->ai_addr, sockpaddr->ai_addrlen)) != NULL) {
		*last_error = Error_GetAddrError;

		goto cleanup;
	}
	send(socket_conn, (const char*)negotiation_packet, 4, 0);
	recv(socket_conn, reply_packet, 2, 0);
	if (socks_addr->auth_enable) {
		char* auth_request = allocheap(strlen(socks_addr->socks_user_auth) + strlen(socks_addr->socks_user_pass) + 20);
		ZeroMemory(auth_request, strlen(socks_addr->socks_user_auth) + strlen(socks_addr->socks_user_pass) + 20);
		auth_request[0] = 1;
		auth_request[1] = strlen(socks_addr->socks_user_auth);
		strcpy(&auth_request[2], socks_addr->socks_user_auth);
	
		auth_request[strlen(socks_addr->socks_user_auth) + 2] = strlen(socks_addr->socks_user_pass);
		strcpy(&auth_request[strlen(auth_request)], socks_addr->socks_user_pass);
		send(socket_conn, (const char*)auth_request, strlen(socks_addr->socks_user_auth) + strlen(socks_addr->socks_user_pass) + 3, 0);
		ZeroMemory(auth_request, 20);
		recv(socket_conn, auth_request, 2, 0);
		if (auth_request[0] != 1 && auth_request[1] != 0) {
			*last_error = Error_socks5_auth_failed;
		}
	}
	if (verify_packet(reply_packet, socks_addr->auth_enable) != sock_s_ok) {
		*last_error = Error_reply_packet_verification;

		goto cleanup;

	}

	
	destaddrsocks = (struct sockaddr_in*)destpaddr->ai_addr;
	memcpy(&final_negotiation_packet[4], &destaddrsocks->sin_addr.S_un.S_addr, 4);
	memcpy(&final_negotiation_packet[8], &destaddrsocks->sin_port, 2);
	send(socket_conn, final_negotiation_packet, 10, 0);
	recv(socket_conn, final_response_packet, 2, 0);
	if (verify_packet(final_response_packet, socks_addr->auth_enable) != sock_s_ok) {
		*last_error = Error_reply_packet_verification;
		goto cleanup;

	}
	*last_error = sock_s_ok;
	
	freeaddrinfo(sockpaddr);
	freeaddrinfo(destpaddr);

cleanup:

	return socket_conn;


#else
	char char_destport[100];
	ZeroMemory(char_destport, 100);
	struct addrinfo dest_addrhints;
	ZeroMemory(&dest_addrhints, sizeof(struct addrinfo));
	if (socks_addr->destaddr == NULL)
		return Error_nosock_ip;
	if (socks_addr->destport == 0)
		return Error_zero_port;
	_itoa_str(socks_addr->destport, char_destport);

	struct addrinfo* destpaddr = NULL;
	dest_addrhints.ai_family = AF_UNSPEC;
	dest_addrhints.ai_socktype = SOCK_STREAM;
	dest_addrhints.ai_protocol = IPPROTO_TCP;

	WSADATA ws_data;
	if ((WSAStartup(MAKEWORD(2, 2), &ws_data)) != NULL) {
		*last_error = Error_WSA_Socks;
		return -1;
	}
	if (getaddrinfo(socks_addr->destaddr, char_destport, &dest_addrhints, &destpaddr) != NULL) {
		DWORD sz = GetLastError();

		*last_error = Error_GetAddrError;
		return -1;

	}
	if (((socket_conn = socket(destpaddr->ai_family, destpaddr->ai_socktype, destpaddr->ai_protocol))) == -1) {
		*last_error = Error_SocksConnect;
		return -1;
	}
	if ((connect(socket_conn, destpaddr->ai_addr, destpaddr->ai_addrlen)) == SOCKET_ERROR) {
		return Error_SocksConnect;
	}

	freeaddrinfo(destpaddr);
	*last_error = 0;
	return socket_conn;

#endif
}
int socket_send_get_request(Psocket_address sock_addr, char* content, char* get_request_buffer, char* output, int ot_len) {
	ULONG error;
	SOCKET current_sock = NULL;
	current_sock = socket_connect(sock_addr, current_sock, &error);

	char* get = (char*)"GET ";
	char* http = (char*)" HTTP/1.1\r\n";
	char* szhost = (char*)"Host: ";
	char* back = (char*)"\r\n\r\n";

	strcat(get_request_buffer, get);
	strcat(get_request_buffer, content);
	strcat(get_request_buffer, http);
	strcat(get_request_buffer, szhost);
	strcat(get_request_buffer, sock_addr->destaddr);
	strcat(get_request_buffer, back);
	send(current_sock, get_request_buffer, strlen(get_request_buffer), 0);
	delay(1);
	recv(current_sock, output, ot_len, 0);
	shutdown(current_sock, SD_SEND);
	closesocket(current_sock);
	WSACleanup();
	return 0;
}
int socket_send_post_request(Psocket_address socks_addr, char* content_dest, char* content_length, char* szcontent, char* post_request_buffer, char* ot_buf, int ot_len) {
	SOCKET current_socket = NULL;
	ULONG   error = sock_s_ok;
	current_socket = socket_connect(socks_addr, current_socket, &error);
	if (error != sock_s_ok)
		return -1;
	char* post = (char*)"POST ";
	char* http = (char*)" HTTP/1.1\r\n";
	char* host = (char*)"Host: ";
	char* back2 = (char*)"\r\n";
	char* cont_len2 = (char*)"Content-Length: ";
	char* cont_type = (char*)"Content-Type: application/x-www-form-urlencoded\r\n";
	char* cont_enc = (char*)"Content-Encoding: binary\r\n";
	char* Accepted_chars = (char*)"Accept-Charset: utf-8\r\n";

	strcat(post_request_buffer, post);
	strcat(post_request_buffer, content_dest);
	strcat(post_request_buffer, http);
	strcat(post_request_buffer, host);
	strcat(post_request_buffer, socks_addr->destaddr);
	strcat(post_request_buffer, back2);
	strcat(post_request_buffer, cont_type);
	strcat(post_request_buffer, cont_enc);
	strcat(post_request_buffer, cont_len2);
	strcat(post_request_buffer, content_length);
	strcat(post_request_buffer, back2);
	strcat(post_request_buffer, Accepted_chars);
	strcat(post_request_buffer, back2);
	strcat(post_request_buffer, szcontent);
	send(current_socket, post_request_buffer, strlen(post_request_buffer), 0);
	delay(1);
	recv(current_socket, ot_buf, ot_len, 0);
	shutdown(current_socket, SD_SEND);
	closesocket(current_socket);
	WSACleanup();
	return 0;
}
int socket_get_content_length(Psocket_address socks_addr, char* content, char* get_request_buffer, char* buffer, DWORD * ret_len) {
	char* temp1 = NULL;
	char* temp2 = NULL;
	char* content_length = "Content-Length";
	char* back = "\r\n";
	DWORD dwlen = 0;
	DWORD result = 0;
	result = socket_send_get_request(socks_addr, content, get_request_buffer, buffer, SOCKET_GET_CONTENTLEN_DEFAULT_SIZE);
	if (result != 0) {
		return -1;

	}
	char* temp3 = allocheap(100);
	ZeroMemory(temp3, 100);

	temp1 = StrStrA(&buffer[10], content_length);
	if (temp1 == NULL)
		return -1;
	temp2 = strtok(temp1, back);
	if (!temp2)
		return -1;
	dwlen = strlen(content_length);
	ZeroMemory(temp3, 100);
	memcpy(temp3, &temp2[dwlen] + 1, 100);
	dwlen = StrToIntA(temp3 + 1); 
	if (dwlen == 0) {
		dwlen = StrToIntA(temp3 + 2);
		if (dwlen == 0) {
			
			dwlen = StrToIntA(temp3 + 3);
			if (dwlen == 0) {
				freeheap(temp3);
				return -1;
			}
		}
	}

	freeheap(temp3);
	memcpy((void*)ret_len, (void*)& dwlen, sizeof(DWORD));
	return 0;
}
char* socket_download_file(Psocket_address socks_addr, char* content, DWORD length, DWORD * written_size, char* download_buffer) {
	BOOL error_occured = FALSE;
	SOCKET current_socket = NULL;
	ULONG error;
	char* get = (char*)"GET "; 
	char* http = (char*)" HTTP/1.1\r\n";
	char* host = (char*)"Host: ";
	char* back = (char*)"\r\n\r\n";
	char* cont_len = (char*)"Content-Length";

	DWORD written = 0, szrealloc = SOCKET_GET_SIZE + length, x = 0;
	char* totalfile = (char*)allocheap(szrealloc);
	if (totalfile == NULL)
		return NULL;
	current_socket = socket_connect(socks_addr, current_socket, &error);
	if (error != sock_s_ok)
		return -1;
	if (*content == NULL)
		return NULL;
	if (*socks_addr->destaddr == NULL)
		return NULL;
	strcat(download_buffer, get);
	strcat(download_buffer, content);
	strcat(download_buffer, http);
	strcat(download_buffer, host);
	strcat(download_buffer, socks_addr->destaddr);
	strcat(download_buffer, back);
	send(current_socket, download_buffer, strlen(download_buffer), 0);
	do {
		Sleep(0x800);
		x = recv(current_socket, totalfile + written, length, 0);
		written += x;
		totalfile = (char*)reallocheap((LPVOID)totalfile, szrealloc += length);

	} while (x > 0);
	memcpy((void*)written_size, &written, sizeof(DWORD));
	shutdown(current_socket, SD_SEND);
	closesocket(current_socket);
	WSACleanup();
	return totalfile;

}
char* socket_post_download(Psocket_address sock_address, char* content_dest, char* content_length, char* szcontent, char* post_Request_buffer, DWORD length, DWORD * written_size) {
	DWORD written = 0, x = 0, szrealloc = length + SOCKET_GET_SIZE;
	char* totalfile = (char*)allocheap(length);
	SOCKET current_socket;
	ULONG error;
	current_socket = socket_connect(sock_address, current_socket, &error);
	if (error != sock_s_ok)
		return -1;

	char* post = (char*)"POST ";
	char* get = (char*)"GET "; 
	char* http = (char*)" HTTP/1.1\r\n";
	char* host = (char*)"Host: ";
	char* back = (char*)"\r\n\r\n";
	char* cont_len = (char*)"Content-Length";
	char* cont_len2 = (char*)"Content-Length: ";

	char* back2 = (char*)"\r\n";
	char* cont_type = (char*)"Content-Type: application/x-www-form-urlencoded\r\n";
	char* cont_enc = (char*)"Content-Encoding: binary\r\n";
	char* Accepted_chars = (char*)"Accept-Charset: utf-8\r\n";
	
	strcat(post_Request_buffer, post);
	strcat(post_Request_buffer, content_dest);
	strcat(post_Request_buffer, http);
	strcat(post_Request_buffer, host);
	strcat(post_Request_buffer, sock_address->destaddr);
	strcat(post_Request_buffer, back2);
	strcat(post_Request_buffer, cont_type);
	strcat(post_Request_buffer, cont_enc);
	strcat(post_Request_buffer, cont_len2);
	strcat(post_Request_buffer, content_length);
	strcat(post_Request_buffer, back2);
	strcat(post_Request_buffer, Accepted_chars);
	strcat(post_Request_buffer, back2);
	strcat(post_Request_buffer, szcontent);

	send(current_socket, post_Request_buffer, strlen(post_Request_buffer), 0);
	do {
		Sleep(0x800);
		x = recv(current_socket, totalfile + written, length, 0);
		written += x;
		totalfile = (char*)reallocheap((LPVOID)totalfile, szrealloc += length);

	} while (x > 0);
	memcpy((void*)written_size, &written, sizeof(DWORD));
	shutdown(current_socket, SD_SEND);
	closesocket(current_socket);
	WSACleanup();
	return totalfile;
}
