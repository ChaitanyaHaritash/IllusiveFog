
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <ShlObj.h>
#pragma comment(lib,"Shlwapi.lib")

#pragma comment (lib, "Ws2_32.lib")
#include "customcrt/crtstring.h"
#include "common/reporter.h"
#include "common/allocation.h"
#define SOCKADDRESS_SIZE 30
#define DESTADDRESS_SIZE 30
#define PORT_SIZE 10
#define SOCKET_GET_CONTENTLEN_DEFAULT_SIZE 300
#define SOCKET_GET_SIZE 320
#define SOCKET_POST_SIZE 500

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
	Error_get_content_length_failed = -35,
	Error_socks5_auth_failed=-36
};
typedef struct socket_address {
	char* destaddr;
	char* sockaddr;
	DWORD destport;
	DWORD sockport;
	char* socks_user_auth;
	char* socks_user_pass;
	BOOL auth_enable;
}socket_address,*Psocket_address;
int socket_send_get_request(Psocket_address sock_addr, char* content, char* get_request_buffer, char* output, int ot_len);
int socket_get_content_length(Psocket_address socks_addr, char* content, char* get_request_buffer, char* buffer, DWORD* ret_len); 
Psocket_address form_socket_address(char* sockip, DWORD sockport, char* destip, DWORD destport, BOOL bauth_enable, char* socks_user_auth, char* socks_pass_auth);
SOCKET socket_connect(Psocket_address socks_addr);
void free_socket_address(Psocket_address sock_addr);
char* socket_download_file(Psocket_address socks_addr, char* content, DWORD length, DWORD* written_size, char* download_buffer);
char* socket_post_download(Psocket_address sock_address, char* content_dest, char* content_length, char* szcontent, char* post_Request_buffer, DWORD length, DWORD* written_size);
int socket_send_post_request(Psocket_address socks_addr, char* content_dest, char* content_length, char* szcontent, char* post_request_buffer, char* ot_buf, int ot_len);
