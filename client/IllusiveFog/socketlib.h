
#ifdef SOCKS5_AUTH
#define SOCKS5
#endif
#ifdef SOCKS5
#define SOCKS
#else
#endif

#ifdef SOCKS4
#define SOCKS
#endif

#define MAX_AUTH_LEN 250


#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")

enum sock_result {
	sock_s_ok = 0,
	Error_nosock_ip = -1,
	Error_nosock_port = -2,
	Error_zero_port = -3,
	Error_WSA_Socks = -4,
	Error_GetAddrError = -5,
	Error_InvalidSocks = -6,
	Error_SocksConnect = -7,
	Error_Send = -8,
	Error_Recv = -9,
	Error_reply_packet_verification = -10,
	content_null = -11,
	host_null = -12,
	get_request_buffer_size_invalid = -13,
	get_request_buffer_heap_corrupted = -14,
	get_request_output_buffer_size_invalid = -15,
	get_content_length_invalid_temp1 = -16,
	get_content_length_invalid_temp2 = -17,
	post_Error_no_content = -18,
	post_Error_no_content_length = -19,
	post_Error_no_host = -21,
	post_Error_heap_corruption = -22,
	invalid_post_request_send = -23,
	invalid_post_request_recv = -24,
	invalid_post_request = -25,
	post_request_heap_corruption_recv = -26,
	download_content_null = -27,
	download_host_null = -28,
	download_buffer_heap_corrupted = -29,
	download_file_heap_corrupted = -30,
	Error_waitable_timer_handle = -31,
	Error_set_waitable_timer = -32,
	Error_no_waitiable_timer = -33,
	Error_wait_for_single_object = -34,
	Error_get_content_length_failed = -35
};
enum socksize {
	sock_addr_size = 50,
	dest_addr_size = 50,
	char_sockport_size = 10,
	char_destport_size = 10,
	response_packet_size = 10,
	final_negotiation_packet_size = 10,
	final_response_packet_size = 2,
	get_request_extra_space = 150,
	get_content_length_buffer_size = 320,
	get_content_length_request_size = 300,
	post_request_extra_space = 200,
	socks_auth_max_user_size = 100,
	socks_auth_max_pass_size = 100
};
class socketlib {
private:

	char negotiation_packet[10];
	char reply_packet[response_packet_size];
	char final_negotiation_packet[final_negotiation_packet_size];
	char final_response_packet[final_response_packet_size];
	sockaddr_in* destaddr = NULL;
	sock_result socket_result;
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
	char* temp1 = NULL;
	char* temp2 = NULL;
	char* temp3 = (char*)malloc(100);
	DWORD content_length = 0;
	HANDLE htimer = NULL;
	LARGE_INTEGER socket_timer;
	DWORD timer = this->socks_timer * 1000; 

	char auth_request[MAX_AUTH_LEN + 20];


public:
	bool auth_enabled;
	char _set_user_auth[socks_auth_max_user_size + 1];
	char _set_pass_auth[socks_auth_max_pass_size + 1];

	char _sockaddr[sock_addr_size];
	int  _sockport;
	char _destaddr[dest_addr_size];
	int _destport;
	DWORD socks_timer = 0;
	socketlib();
	DWORD last_error = 0;
	DWORD dw_connect = 0;
	WSADATA wsdata;
	char char_sockport[char_sockport_size];
	char char_destport[char_destport_size];
	struct hostent* _host;
	struct hostent* _desthost;
	SOCKET socket_conn = INVALID_SOCKET;
#ifdef SOCKS
	sock_result set_sockaddr(const char* addr, int port);
	sock_result set_socksauth(char* socks_user_auth, char* socks_pass_auth);
#endif
	sock_result set_destaddr(const char* addr, int port);
	sock_result verify_reply_packets(char* packets, BOOL socks_auth);
	void socket_connect_cleanup();
	sock_result socket_connect();
	struct addrinfo dest_addrhints;
	struct addrinfo sock_addrhints;
	PADDRINFOA destpaddr = (PADDRINFOA)malloc(sizeof(ADDRINFOA));
	PADDRINFOA sockpaddr = (PADDRINFOA)malloc(sizeof(ADDRINFOA));
	sock_result send_get_request(char* content, char* get_request_buffer, char* host, char* output, int ot_len);
	sock_result send_post_request(char* content_dest, char* content_length, char* szcontent, char* szhost, char* post_request_buffer, char* ot_buf, int ot_len);
	sock_result socket_get_content_length(char* content, char* host, char* get_request_buffer, char* buffer, DWORD* ret_len);
	char* download(char* content, char* sz_host, int length, DWORD written_size, char* download_buffer);
	sock_result set_socks_timer();
	sock_result socks_wait();
};