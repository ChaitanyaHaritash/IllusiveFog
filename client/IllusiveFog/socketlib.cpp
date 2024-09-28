#include "socketlib.h"

#ifdef SOCKS
sock_result socketlib::set_socksauth(char* set_socksuser_auth, char* set_socks_pass_auth) {
	this->negotiation_packet[0] = 5;
	this->negotiation_packet[1] = 2;
	this->negotiation_packet[2] = 0;
	this->negotiation_packet[3] = 2;
	this->auth_enabled = true;
	ZeroMemory(this->_set_user_auth, socks_auth_max_user_size);
	strcpy(this->_set_user_auth, set_socksuser_auth);
	ZeroMemory(this->_set_pass_auth, socks_auth_max_pass_size);
	strcpy(this->_set_pass_auth, set_socks_pass_auth);

	return sock_s_ok;
}
#endif
#ifdef SOCKS
sock_result socketlib::verify_reply_packets(char* packets, BOOL socks_auth) {
	if (socks_auth) {
		if (packets[1] == 2 && packets[0] == 5) {
			return sock_s_ok;
		}
	}
	if (packets[1] == 0 && packets[0] == 5) {
		return sock_s_ok;
	}
	return Error_reply_packet_verification;
}
#endif
socketlib::socketlib() {
#ifdef SOCKS
	ZeroMemory(this->negotiation_packet, 3);
	ZeroMemory(this->reply_packet, response_packet_size);
	ZeroMemory(this->final_negotiation_packet, final_negotiation_packet_size);
	ZeroMemory(this->final_response_packet, final_response_packet_size);
	this->negotiation_packet[0] = 5;
	this->negotiation_packet[1] = 1;
	this->negotiation_packet[2] = 0;
	this->final_negotiation_packet[0] = 5;
	this->final_negotiation_packet[1] = 1;
	this->final_negotiation_packet[2] = 0;
	this->final_negotiation_packet[3] = 1;


#endif

}
#ifdef SOCKS
sock_result socketlib::set_sockaddr(const char* addr, int port) {
	ZeroMemory(this->_sockaddr, sock_addr_size);
	lstrcpy(_sockaddr, addr);
	this->_sockport = port;
	return sock_s_ok;
}
#endif

sock_result socketlib::set_destaddr(const char* addr, int port) {
	ZeroMemory(this->_destaddr, dest_addr_size);
	lstrcpy(this->_destaddr, addr);
	this->_destport = port;
	return sock_s_ok;
}
#ifdef SOCKS
void socketlib::socket_connect_cleanup() {
	ZeroMemory(char_destport, char_destport_size);
	ZeroMemory(char_sockport, char_sockport_size);

}
#endif



sock_result socketlib::socket_connect() {

#ifdef SOCKS

	if (this->_sockaddr == NULL)
		return Error_nosock_ip;
	if (this->_destaddr == NULL)
		return Error_nosock_port;
	if (this->_destport == 0)
		return Error_zero_port;
	if (this->_sockport == 0)
		return Error_zero_port;
	dw_connect = WSAStartup(MAKEWORD(2, 2), &wsdata);
	if (dw_connect != sock_s_ok) {
		this->last_error = GetLastError();
		return Error_WSA_Socks;
	}
	ZeroMemory(&this->dest_addrhints, sizeof(&this->dest_addrhints));
	ZeroMemory(&this->sock_addrhints, sizeof(&this->sock_addrhints));
	dest_addrhints.ai_family = AF_INET;
	this->dest_addrhints.ai_socktype = SOCK_STREAM;
	this->dest_addrhints.ai_protocol = IPPROTO_TCP;
	ZeroMemory(char_destport, char_destport_size);
	ZeroMemory(char_sockport, char_sockport_size);
	_itoa_s(_destport, char_destport, 10);
	_itoa_s(_sockport, char_sockport, 10);
	dw_connect = getaddrinfo(this->_destaddr, char_destport, &dest_addrhints, &destpaddr);
	if (dw_connect != 0) {
		this->last_error = GetLastError();
		return Error_GetAddrError;
	}
	ZeroMemory(&this->sock_addrhints, sizeof(&this->sock_addrhints));
	this->sock_addrhints.ai_family = AF_INET;
	this->sock_addrhints.ai_socktype = SOCK_STREAM;
	this->sock_addrhints.ai_protocol = IPPROTO_TCP;
	dw_connect = getaddrinfo(this->_sockaddr, char_sockport, &sock_addrhints, &sockpaddr);
	if (dw_connect != 0) {
		this->last_error = GetLastError();
		return Error_GetAddrError;
	}
	if ((socket_conn = socket(sockpaddr->ai_family, sockpaddr->ai_socktype, sockpaddr->ai_protocol)) == -1) {
		this->last_error = GetLastError();
		this->socket_connect_cleanup();
		return Error_InvalidSocks;

	}
	setsockopt(socket_conn, SOL_SOCKET, SO_RCVTIMEO, (char*)& timer, sizeof(timer));

	if (connect(socket_conn, sockpaddr->ai_addr, sockpaddr->ai_addrlen) != 0) {
		this->last_error = GetLastError();
		this->socket_connect_cleanup();
		return Error_SocksConnect;
	}

	dw_connect = send(socket_conn, (const char*)this->negotiation_packet, 4, 0); //add checks
	if (dw_connect == SOCKET_ERROR) {
		this->last_error = SOCKET_ERROR;
		this->socket_connect_cleanup();
		return Error_Send;
	}
	dw_connect = recv(socket_conn, this->reply_packet, 3, 0); //add checks
	if (dw_connect == SOCKET_ERROR) {
		this->last_error = SOCKET_ERROR;
		this->socket_connect_cleanup();
		return Error_Recv;
	}


	this->dw_connect = this->verify_reply_packets(this->reply_packet, this->auth_enabled);
	if (auth_enabled) {
		ZeroMemory(auth_request, MAX_AUTH_LEN + 20);
		auth_request[0] = 1;
		auth_request[1] = strlen(_set_user_auth);
		strcpy(&auth_request[2], _set_user_auth);
		//convert le
		auth_request[strlen(_set_user_auth) + 2] = strlen(_set_pass_auth);
		strcpy(&auth_request[strlen(auth_request)], _set_pass_auth);
		send(socket_conn, (const char*)auth_request, strlen(_set_user_auth) + strlen(_set_pass_auth) + 3, 0);
		ZeroMemory(auth_request, MAX_AUTH_LEN + 20);
		recv(socket_conn, auth_request, 2, 0);
		if (auth_request[0] == 1 && auth_request[1] == 0) {
			dw_connect = sock_s_ok;
		}
	}


	if (dw_connect == sock_s_ok) {

		destaddr = (sockaddr_in*)destpaddr->ai_addr;
		memcpy(&final_negotiation_packet[4], &destaddr->sin_addr.S_un.S_addr, 4);
		memcpy(&final_negotiation_packet[8], &destaddr->sin_port, 2);
		this->dw_connect = send(socket_conn, final_negotiation_packet, final_negotiation_packet_size, 0);
		if (dw_connect == SOCKET_ERROR) {
			this->last_error = SOCKET_ERROR;
			this->socket_connect_cleanup();
			return Error_Send;
		}
		this->dw_connect = recv(socket_conn, this->final_response_packet, final_response_packet_size, 0);
		if (dw_connect == SOCKET_ERROR) {
			this->last_error = SOCKET_ERROR;
			this->socket_connect_cleanup();
			return Error_Recv;
		}

		this->dw_connect = this->verify_reply_packets(this->final_response_packet, this->auth_enabled);


		if (dw_connect == sock_s_ok) {

			FreeAddrInfoA(sockpaddr);
			FreeAddrInfoA(destpaddr);
			return sock_s_ok;
		}
		else { this->socket_connect_cleanup(); return Error_reply_packet_verification; }
	}
	else {
		this->socket_connect_cleanup();
		return Error_reply_packet_verification;
	}
	return sock_s_ok;



#else

	if (this->_destaddr == NULL)
		return Error_nosock_port;
	if (this->_destport == 0)
		return Error_zero_port;
	dw_connect = WSAStartup(MAKEWORD(2, 2), &wsdata);
	if (dw_connect != sock_s_ok) {
		this->last_error = GetLastError();
		return Error_WSA_Socks;
	}
	ZeroMemory(&this->dest_addrhints, sizeof(&this->dest_addrhints));
	dest_addrhints.ai_family = AF_UNSPEC;
	this->dest_addrhints.ai_socktype = SOCK_STREAM;
	this->dest_addrhints.ai_protocol = IPPROTO_TCP;
	ZeroMemory(char_destport, char_destport_size);
	_itoa_s(_destport, char_destport, 10);
	dw_connect = getaddrinfo(this->_destaddr, char_destport, &dest_addrhints, &destpaddr);
	if (dw_connect != 0) {
		this->last_error = GetLastError();
		return Error_GetAddrError;
	}
	if ((this->socket_conn = socket(destpaddr->ai_family, destpaddr->ai_socktype, destpaddr->ai_protocol)) == -1) {
		this->last_error = GetLastError();
		return Error_InvalidSocks;

	}
	if ((connect(socket_conn, destpaddr->ai_addr, destpaddr->ai_addrlen)) == SOCKET_ERROR) {
		return Error_SocksConnect;
	}
	FreeAddrInfoA(destpaddr);
	return sock_s_ok;


#endif

}
sock_result socketlib::send_get_request(char* content, char* get_request_buffer, char* host, char* output, int ot_len) {
	this->socket_result = socket_connect();
	if (socket_result != sock_s_ok /*|| this->last_error != sock_s_ok*/)
		return this->socket_result;
	if (*content == NULL)
		return content_null;
	if (*host == NULL)
		return host_null;
	__try {
		/*strcat(get_request_buffer, this->get);
		strcat(get_request_buffer, content);
		strcat(get_request_buffer, this->http);
		strcat(get_request_buffer, this->host);
		strcat(get_request_buffer, host);
		strcat(get_request_buffer, this->back);*/
		strncat(get_request_buffer, this->get, strlen(this->get));
		strncat(get_request_buffer, content, strlen(content));
		strncat(get_request_buffer, this->http, strlen(this->http));
		strncat(get_request_buffer, this->host, strlen(this->host));
		strncat(get_request_buffer, host, strlen(host));
		strncat(get_request_buffer, this->back, strlen(this->back));

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		this->dw_connect = get_request_buffer_size_invalid;
		return get_request_buffer_heap_corrupted;
	}
	__try {
		this->dw_connect = send(socket_conn, get_request_buffer, strlen(get_request_buffer), 0);
		if (this->dw_connect == SOCKET_ERROR) {
			this->dw_connect = WSAGetLastError();
			return Error_Send;

		}

		this->set_socks_timer();
		this->socks_wait();

		/*	Sleep(0x800);
		*/	this->dw_connect = recv(socket_conn, output, ot_len, 0);
		if (this->dw_connect == SOCKET_ERROR) {
			this->dw_connect = WSAGetLastError();
			return Error_Recv;

		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		this->dw_connect = get_request_output_buffer_size_invalid;
		return get_request_buffer_heap_corrupted;
	}
	shutdown(socket_conn, SD_SEND);
	closesocket(socket_conn);

	WSACleanup();
	return sock_s_ok;


}
sock_result socketlib::socket_get_content_length(char* content, char* host, char* get_request_buffer, char* buffer, DWORD* ret_len) {
	this->temp1 = NULL;
	this->temp2 = NULL;
	ZeroMemory(this->temp3, 100);

	this->socket_result = this->send_get_request(content, get_request_buffer, host, buffer, get_content_length_request_size);
	if (this->socket_result != sock_s_ok)
		return Error_get_content_length_failed;

	temp1 = strstr(&buffer[10], this->cont_len);
	if (temp1 == NULL) {
		this->dw_connect = get_content_length_invalid_temp1;
		return get_content_length_invalid_temp1;
	}
	char* next = NULL;
	temp2 = strtok_s(temp1, this->back2, &next);
	if (temp2 == NULL) {
		this->dw_connect = get_content_length_invalid_temp2;
		return get_content_length_invalid_temp2;

	}
	this->dw_connect = strlen(this->cont_len);
	ZeroMemory(temp3, 100);
	memcpy(temp3, &temp2[this->dw_connect] + 1, 100);
	this->content_length = atoi(temp3);  
	memcpy((void*)ret_len, &this->content_length, sizeof(DWORD));
	ZeroMemory(this->temp3, 100);

	temp1 = NULL;
	temp2 = NULL;

	return sock_s_ok;

}

sock_result socketlib::send_post_request(char* content_dest, char* content_length, char* szcontent, char* szhost, char* post_request_buffer, char* ot_buf, int ot_len) {
	if (*content_dest == NULL)
		return 	post_Error_no_content;
	if (*content_length == NULL)
		return post_Error_no_content_length;
	if (*szcontent == NULL)
		return post_Error_no_content;
	if (*szhost == NULL)
		return post_Error_no_host;
	this->socket_result = this->socket_connect();
	if (this->socket_result != sock_s_ok /*|| this->last_error != sock_s_ok*/)
		return this->socket_result;

	__try {
		strcpy(post_request_buffer, post);
		strcat(post_request_buffer, content_dest);
		strcat(post_request_buffer, http);
		strcat(post_request_buffer, host);
		strcat(post_request_buffer, szhost);
		strcat(post_request_buffer, back2);
		strcat(post_request_buffer, cont_type);
		strcat(post_request_buffer, cont_enc);
		strcat(post_request_buffer, cont_len2);
		strcat(post_request_buffer, content_length);
		strcat(post_request_buffer, back2);
		strcat(post_request_buffer, Accepted_chars);
		strcat(post_request_buffer, back2);
		strcat(post_request_buffer, szcontent);


	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return post_Error_heap_corruption;
	}
	__try {
		this->dw_connect = send(socket_conn, post_request_buffer, strlen(post_request_buffer), 0);
		if (dw_connect == SOCKET_ERROR) {
			this->dw_connect = WSAGetLastError();;
			return Error_Send;
		}

		/*this->set_socks_timer();
		this->socks_wait();
		*/Sleep(0x800);
		this->dw_connect = recv(socket_conn, ot_buf, ot_len, 0);
		if (dw_connect == SOCKET_ERROR) {
			this->dw_connect = WSAGetLastError();
			return Error_Recv;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		this->dw_connect = invalid_post_request;
		return post_request_heap_corruption_recv;
	}

	shutdown(socket_conn, SD_SEND);
	closesocket(socket_conn);
	WSACleanup();
	return sock_s_ok;

}


char* socketlib::download(char* content, char* sz_host, int length, DWORD written_size, char* download_buffer) {
	DWORD written = 0, x = 0, szrealloc = length;
	char* TotalFile = (char*)malloc(length);
	if (*content == NULL)
		return NULL;
	if (*sz_host == NULL)
		return NULL;
	this->socket_result = this->socket_connect();
	if (this->socket_result != sock_s_ok /*|| this->last_error != sock_s_ok*/)
		return NULL;
	__try {
		strcat(download_buffer, this->get);
		strcat(download_buffer, content);
		strcat(download_buffer, this->http);
		strcat(download_buffer, this->host);
		strcat(download_buffer, sz_host);
		strcat(download_buffer, this->back);
		send(socket_conn, download_buffer, strlen(download_buffer), 0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return NULL;
	}

	__try {
		do {
			this->set_socks_timer();
			this->socks_wait();
		
			x = recv(socket_conn, TotalFile + written, length, 0);
			written += x;
			TotalFile = (char*)realloc(TotalFile, szrealloc += length);
		
		} while (x > 0);
		memcpy((void*)written_size, &written, sizeof(DWORD));
		shutdown(socket_conn, SD_SEND);
		closesocket(socket_conn);
		WSACleanup();

		return TotalFile;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return NULL;
	}


}
sock_result socketlib::set_socks_timer() {
	if (this->socks_timer == 0)
		Error_no_waitiable_timer;
	this->socket_timer.QuadPart = socks_timer * -100000000LL;
	this->htimer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (this->htimer == NULL) {
		this->last_error = GetLastError();
		return Error_waitable_timer_handle;
	}
	if (!SetWaitableTimer(this->htimer, &this->socket_timer, 0, NULL, NULL, 0)) {
		this->last_error = GetLastError();
		return Error_set_waitable_timer;
	}
	return sock_s_ok;
}
sock_result socketlib::socks_wait() {
	if (WaitForSingleObject(this->htimer, INFINITE) != WAIT_OBJECT_0) {
		this->last_error = GetLastError();
		return Error_wait_for_single_object;
	}
	CloseHandle(this->htimer);
	return sock_s_ok;
}

