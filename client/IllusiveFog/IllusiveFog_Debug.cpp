#include "IllusiveFog.h"
#ifdef _DEBUG

void IllusiveFog::IllusiveFog::IllusiveFog_debug(IllusiveFog_result IllusiveFog_debug_result) {
	switch (IllusiveFog_debug_result) {
	case IllusiveFog_no_sockip:
		OutputDebugString("IllusiveFog::form_address: invalid socket server ip provided");
		break;
	case IllusiveFog_no_hostip:
		OutputDebugString("IllusiveFog::form_address: invalid host server ip provided");
		break;
	case IllusiveFog_no_sockport:
		OutputDebugString("IllusiveFog::form_address: invalid socket server port ");
		break;
	case IllusiveFog_no_hostport:
		OutputDebugString("IllusiveFog::form_address: invalid host server port");
		break;
	case IllusiveFog_post_request_heap_corrupted:
		OutputDebugString("IllusiveFog::form_IllusiveFog_agent_post_request: invalid initial agent post request");
		break;
	case form_agent_session_heap_corrupted:
		OutputDebugString("IllusiveFog::form_agent_session: invalid agent session received ");
		break;
	case IllusiveFog_get_agent_info_failed:
		OutputDebugString("IllusiveFog::GetAgentInfo: failed to receive agent information for intial agent post request");
		break;
	case set_agent_session_info_error:
		OutputDebugString("IllusiveFog::SetAgentSession_info: invalid agent session information received");
		break;
	case IllusiveFog_heap_corrupted_receive_jobs:
		OutputDebugString("IllusiveFog::IllusiveFog_receive_jobs: invalid agent job received");
		break;
		//case IllusiveFog_error_plugin_already_loaded:
	   // OutputDebugString("IllusiveFog::IllusiveFog_load_plugin: agent has already loaded plugin");
	   // break;
	case IllusiveFog_error_failed_send_agent_info:
		OutputDebugString("IllusiveFog::send_IllusiveFog_agent_info: agent failed to send initial agent post request");
		break;
	case IllusiveFog_error_form_hex_command_failed:
		OutputDebugString("IllusiveFog::IllusiveFog_form_hexcommands: invalid agent hex commands provided");
		break;
	case IllusiveFog_error_plugin_load_failed:
		OutputDebugString("IllusiveFog::IllusiveFog_load_plugin: IllusiveFog plugin load failed");
		break;
	case IllusiveFog_error_plugin_parse_failed:
		OutputDebugString("IllusiveFog::form_IllusiveFog_agent_requirements: IllusiveFog invalid plugin value received");
		break;
	case IllusiveFog_error_plugin_set_failed:
		OutputDebugString("IllusiveFog::IllusiveFog_set_plugin: failed to set plugin export");
		break;
	case IllusiveFog_error_IllusiveFog_invoke_plugin_failed:
		OutputDebugString("IllusiveFog::IllusiveFog_invoke_plugin : failed to invoke plugin");
		break;
	case IllusiveFog_error_agent_plugin_req_failed:
		OutputDebugString("IllusiveFog::form_IllusiveFog_agent_plugin_requirements: unable to parse with plugin request");
		break;
	default:
		OutputDebugString("IllusiveFog::unknown_errorcode: unknown error code");
		break;
	}

}
void IllusiveFog::IllusiveFog::IllusiveFog_plugin_manager_debug(plugin_manager_result plugin_manager_debug_result) {
	switch (plugin_manager_debug_result) {
	case plugin_manager_invalid_plugin_thread_launched:
		OutputDebugString("PluginManager::plugin_handler: plugin export maybe null or invalid");
		break;
	case plugin_manager_plugin_param_send_thread_failed:
		OutputDebugString("PluginManager::plugin_manager_invoke_plugin: sending plugin parameter to plugin thread failed");
		break;

	default:
		OutputDebugString("PluginManager::plugin_manager_unknown: unknown error code");
	}
}
void IllusiveFog::IllusiveFog::IllusiveFog_debug_socket(sock_result socket_debug_result) {
	switch (socket_debug_result) {

	}
}
void IllusiveFog::IllusiveFog::IllusiveFog_debug_memory_manager(memory_manager_result memory_manager_debug_result) {
	switch (memory_manager_debug_result) {
	case invalid_temp_memory_freed:
		OutputDebugString("MemoryManager::FreeTemporary: invalid temporary  heap freed");
		break;
	case invalid_heap_freed:
		OutputDebugString("MemoryManager::FreeMemory: invalid heap freed");
		break;
	default:
		OutputDebugString("MemoryManager::unknown_error_code : unknown error code");
		break;
	}
}
void IllusiveFog::IllusiveFog::IllusiveFog_plugin_debug(plugin_result plugin_debug_result) {
	switch (plugin_debug_result) {
	case plugin_setpath_heap_corrupted:
		OutputDebugString("Plugin::set_plugin_paths: invalid plugin path received");
		break;
	case plugin_invalid_job:
		OutputDebugString("Plugin::parse_plugin: invalid plugin and job received");
		break;
	case plugin_error_set_plugin_hex_command:
		OutputDebugString("Plugin::set_plugin_hex_commands: invalid hex commands received");
		break;
	case plugin_error_plugin_parsing_failed:
		OutputDebugString("Plugin::parse_plugin: invalid plugin received");
		break;
	case plugin_error_load_plugin_failed:
		OutputDebugString("IllusiveFog::form_IllusiveFog_agent_plugin_requirements: failed to load plugin,received invalid buffer");
		break;
	default:
		OutputDebugString("Plugin::unknown_error_code: unknown error code");
		break;

	}
}
void IllusiveFog::IllusiveFog::IllusiveFog_debug_utils(utils_result util_debug_result) {
	switch (util_debug_result) {
	case utils_aes_decryption_failed:
		OutputDebugString("utils::utils_aes_decrypt: aes decryption failed");
		break;
	case utils_base64_decode_failed:
		OutputDebugString("utils::utils_convert_from_base64: string conversion from base64 failed");
		break;
	case utils_hex_decode_failed:
		OutputDebugString("hex decodde failed");
		break;
	case utils_aes_encryption_failed:
		OutputDebugString("utils::utils_aes_encrypt:aes encryption failed");
		break;
	default:
		OutputDebugString("utils::unknwon_error_code: unknown error code");
		break;
	}
}

#endif