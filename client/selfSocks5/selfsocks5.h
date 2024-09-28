#include <WinSock2.h>
#include <WS2tcpip.h>
#include "network/ntwrkcomms.h"
#include "common/allocation.h"
#include "common/stringconvert.h"
#include "common/reporter.h"
#include "customcrt/crtstring.h"
#include <netfw.h>
#include <Shlwapi.h>
enum socks_client_report_error {
	EC_SUCCESS = 0,
	EC_GENERAL_FAILURE = 1,
	EC_NOT_ALLOWED = 2,
	EC_NET_UNREACHABLE = 3,
	EC_HOST_UNREACHABLE = 4,
	EC_CONN_REFUSED = 5,
	EC_TTL_EXPIRED = 6,
	EC_COMMAND_NOT_SUPPORTED = 7,
	EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};
typedef enum socks_server_version {
	SOCKS5 = 5
};
typedef enum socks_cmd_actions {
	CONNECT = 1,
	BIND = 2,
	UDP_ASSOCIATE = 3
};
typedef enum socks_authetication_methods {
	NO_AUTHETICATION = 0,
	AUTHENTICATION_GSSAPI = 1,
	AUTHENTICATION_USERNAME = 2,
	AUTENTICATION_INVALID = 0xFF
};
typedef enum socks_server_address_type {
	IPV4 = 1,
	DNS = 3,
	IPV6 = 4
};
struct socks5_response {
	unsigned char version;
	unsigned char reply;
	unsigned char reserved;

	union {
		struct sockaddr_in ipv4;
		struct sockaddr_in6  ipv6;

	}ip_type;

};
typedef struct socks_server_info {
	struct sockaddr_in socks_serveraddr_info;
	SOCKET bind_server;
	SOCKET server_socks;
	SOCKET dest_socks;
	char* socketserver_ip;
	int socketserver_port;
	HANDLE thread_event1;
	HANDLE socket_thread;
	char socket_port[100];
}socks_server_info, * Psocks_server_info;
typedef struct thread_server_handle {
	HANDLE hthread;
	struct thread_server_handle* Next;
	DWORD count;
}thread_server_handle, * Pthread_server_handle;
typedef struct socks_negotitate_info {
	struct socks5_response socks_response;

	enum socks_authethication_methods server_authethicated_methods;
	enum socks_cmd_action socks_server_actions;
	enum socks_server_version socks_server_version_select;
	enum socks_server_address_type socks_server_address_support;
	char ip_buffer[250];
	DWORD destport;
	char chr_target_port[100];
	struct addrinfo destaddrinfo;
	ADDRINFOA destpaddr;
	char buffer[1024];
	SOCKET dest_socks;
	SOCKET server_socks;

}socks_negotiate_info, * Psocks_negotitate_info;
#define MAX_HOST 260
#define MAX_SOCKS_THREAD 60
#define DEFAULT_IMAGE_SIZE 5000
void append_first_null(struct thread_server_handle** thread_server, HANDLE h_handle, DWORD dwcount);
void set_fw_rule(BOOL bdisable, char* fw_rule_port);
void add_thread_handle(struct thread_server_handle** thread, HANDLE h_thread, DWORD dwcount);
void remove_thread_handle(struct thread_server_handle** thread, DWORD dwcount);
void check_and_terminate(struct thread_server_handle* server_handles);
void terminate_all(struct thread_server_handle* server_handles);
LONG initialize_server(Psocks_server_info server_info, PULONG status);
LONG accepted_server_request(Psocks_server_info server_info, Psocks_negotitate_info srvr);