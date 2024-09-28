#include <Windows.h>
#include <processthreadsapi.h>
#include "common/reporter.h"
#include "common/stringconvert.h"
#include <stdio.h>
#include <wuapi.h>
typedef struct update_info {
	IUpdateSearcher* update_searcher;
	IUpdateSession* update_session;
	ISearchResult* update_result;
	IUpdateCollection* update_collection;
	IUpdate* update_info;
	IStringCollection* update_string_collection;
}update_info, * Pupdate_info;

typedef enum verbose_mitig_error_code {
	verbose_mitig_success = 0,
	process_mitigs_failed = -51,
	process_dep_enabled = -52,
	process_dep_disabled = -53,
	process_dep_permenant = -54,
	process_dep_temporary = -55,
	process_dep_disable_atl_thunk_emulation = -56,
	process_dep_enable_atl_thunk_emulation = -57,
	process_bottom_up_aslr_enabled = -58,
	process_bottom_up_aslr_disabled = -59,
	process_aslr_enable_force_relocate_image = -60,
	process_aslr_disable_force_relocate_image = -61,
	process_aslr_enable_high_entropy = -62,
	process_aslr_disable_high_entropy = -63,
	process_disallow_stripped_image = -64,
	process_allow_stripped_image = -65,
	process_dyn_code_prohibited = -66,
	process_dyn_code_allowed = -68,
	process_dyn_code_allow_thread_opt_out = -69,
	process_dyn_code_disallow_thread_opt_out = -70,
	process_dyn_code_allow_remote_downgrade = -71,
	process_dyn_code_disallow_remote_downgrade = -72,
	process_handle_check_generate_exception_invalid_handle = -73,
	process_handle_check_inv_handle_generate_exception_disable = -74,
	process_handle_check_inv_handle_usage_ignored = -75,
	process_syscall_win32k_syscalls_blocked_audited = -76,
	process_syscall_win32k_syscalls_blocked = -97,
	process_syscall_win32k_syscalls_allowed = -77,
	process_legacy_dll_extension_points_disabled = -78,
	process_legacy_dll_extension_points_enabled = -79,
	process_cfg_enabled = -80,
	process_cfg_disabled = -81,
	process_cfg_export_functions_indirect_calls_disalled = -82,
	process_cfg_export_functions_indirect_calls_allowed = -98,
	process_cfg_strict_enabled = -83,
	process_cfg_strict_disabled = -84,
	process_bin_sig_policy_signed_only = -85,
	process_bin_sig_policy_store_sign_only = -86,
	process_bin_sig_policy_whql_sign_only = -87,
	process_bin_sig_policy_arbitrary = -88,
	process_system_font_only = -89,
	process_arbitrary_font = -90,
	process_image_policy_no_remote_image = -91,
	process_image_policy_remote_image_allowed = -92,
	process_image_policy_load_image_lowil_prohibited = -93,
	process_image_policy_load_image_arbitrary_il = -94,
	process_image_policy_prefer_system32_image = -95,
	process_image_policy_basic_image_search = -96,
	update_failed_com_object_initialization = -100,
	update_failed_create_update_searcher = -102

};
typedef enum vr_methods {
	no_methods = 0,
	mitigs = 1,
	updt = 2

};
enum verbose_mitig_error_code report_updates(enum tagServerSelection* server_selection, Pupdate_info uinfo, HANDLE hreporter, DWORD threadid);
enum verbose_mitig_error_code update_session(enum tagServerSelection* server_selection, Pupdate_info uinfo, HANDLE reporter_event, DWORD reporter_threadid);
enum vr_methods select_method(char* method);
enum verbose_mitig_error_code report_dep_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_aslr_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_dyn_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_handle_check_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_syscall_disable_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_process_extension_point_disable_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_cfg_polciy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_process_sign_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_font_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);
enum verbose_mitig_error_code report_image_load_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id);