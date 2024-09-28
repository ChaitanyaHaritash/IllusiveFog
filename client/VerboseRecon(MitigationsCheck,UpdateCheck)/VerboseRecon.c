#include "VerboseRecon.h"
#include "common.h"
enum vr_methods select_method(char* method) {
	char* method_temp = NULL;
	enum vr_methods vr2_query;
	vr2_query = no_methods;
	for (int i = 0; i <= VR2_METHODS; i++) {
		method_temp = strstrA(method, vr_methods[i]);
		if (method_temp) {
			if (i == 0) {
				vr2_query = mitigs;
			}
			else if (i == 1) {
				vr2_query = updt;
			}
			else
				vr2_query = no_methods;

		}
	}
	return vr2_query;
}

enum verbose_mitig_error_code get_mitigation_policy(HANDLE hprocess, PROCESS_MITIGATION_POLICY process_mitigs, PVOID buffer, size_t len) {
	if (!GetProcessMitigationPolicy(hprocess, process_mitigs, buffer, len))
		return process_mitigs_failed;
	else return verbose_mitig_success;
}
enum verbose_mitig_error_code report_dep_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_DEP_POLICY dep_policy;
	if ((get_mitigation_policy(current_process, ProcessDEPPolicy, &dep_policy, sizeof(dep_policy)) != verbose_mitig_success)) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (dep_policy.Enable)
		report_ec(process_dep_enabled, hreporter, dwthread_id);
	else
		report_ec(process_dep_disabled, hreporter, dwthread_id);

	if (dep_policy.Permanent)
		report_ec(process_dep_permenant, hreporter, dwthread_id);
	else
		report_ec(process_dep_temporary, hreporter, dwthread_id);
	if (dep_policy.DisableAtlThunkEmulation)
		report_ec(process_dep_disable_atl_thunk_emulation, hreporter, dwthread_id);
	else
		report_ec(process_dep_enable_atl_thunk_emulation, hreporter, dwthread_id);
	ZeroMemory(&dep_policy, sizeof(dep_policy));
	return verbose_mitig_success;


}
enum verbose_mitig_error_code report_aslr_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_ASLR_POLICY aslr_policy;
	if ((get_mitigation_policy(current_process, ProcessASLRPolicy, &aslr_policy, sizeof(aslr_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (aslr_policy.EnableBottomUpRandomization)
		report_ec(process_bottom_up_aslr_enabled, hreporter, dwthread_id);
	else
		report_ec(process_bottom_up_aslr_disabled, hreporter, dwthread_id);
	if (aslr_policy.EnableForceRelocateImages)
		report_ec(process_aslr_enable_force_relocate_image, hreporter, dwthread_id);
	else
		report_ec(process_aslr_disable_force_relocate_image, hreporter, dwthread_id);
	if (aslr_policy.EnableHighEntropy)
		report_ec(process_aslr_enable_high_entropy, hreporter, dwthread_id);
	else report_ec(process_aslr_disable_high_entropy, hreporter, dwthread_id);
	if (aslr_policy.DisallowStrippedImages)
		report_ec(process_disallow_stripped_image, hreporter, dwthread_id);
	else
		report_ec(process_allow_stripped_image, hreporter, dwthread_id);
	return verbose_mitig_success;
}
enum verbose_mitig_error_code report_dyn_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY process_dyn_code_policy;
	if ((get_mitigation_policy(current_process, ProcessDynamicCodePolicy, &process_dyn_code_policy, sizeof(process_dyn_code_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;

	}
	if (process_dyn_code_policy.ProhibitDynamicCode) {
		report_ec(process_dyn_code_prohibited, hreporter, dwthread_id);
		if (process_dyn_code_policy.AllowThreadOptOut)
			report_ec(process_dyn_code_allow_thread_opt_out, hreporter, dwthread_id);
		else report_ec(process_dyn_code_disallow_thread_opt_out, hreporter, dwthread_id);
		if (process_dyn_code_policy.AllowRemoteDowngrade)
			report_ec(process_dyn_code_allow_remote_downgrade, hreporter, dwthread_id);
		else report_ec(process_dyn_code_disallow_remote_downgrade, hreporter, dwthread_id);
	}
	else report(process_dyn_code_allowed, hreporter, dwthread_id);
	return verbose_mitig_success;

}
enum verbose_mitig_error_code report_handle_check_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handle_check_policy;
	if ((get_mitigation_policy(current_process, ProcessStrictHandleCheckPolicy, &handle_check_policy, sizeof(handle_check_policy))) != verbose_mitig_success) {
		if (handle_check_policy.RaiseExceptionOnInvalidHandleReference && handle_check_policy.HandleExceptionsPermanentlyEnabled) {
			report_ec(process_handle_check_generate_exception_invalid_handle, hreporter, dwthread_id);
		}
		else if (handle_check_policy.RaiseExceptionOnInvalidHandleReference)
			report_ec(process_handle_check_inv_handle_generate_exception_disable, hreporter, dwthread_id);
		else
			report_ec(process_handle_check_inv_handle_usage_ignored, hreporter, dwthread_id);

	}
	return verbose_mitig_success;


}
enum verbose_mitig_error_code report_syscall_disable_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY process_syscall_policy;
	if ((get_mitigation_policy(current_process, ProcessSystemCallDisablePolicy, &process_syscall_policy, sizeof(process_syscall_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (process_syscall_policy.DisallowWin32kSystemCalls && process_syscall_policy.AuditDisallowWin32kSystemCalls)
		report_ec(process_syscall_win32k_syscalls_blocked_audited, hreporter, dwthread_id);
	else if (process_syscall_policy.DisallowWin32kSystemCalls)
		report_ec(process_syscall_win32k_syscalls_blocked, hreporter, dwthread_id);
	else
		report_ec(process_syscall_win32k_syscalls_allowed, hreporter, dwthread_id);
	return verbose_mitig_success;
}
enum verbose_mitig_error_code report_process_extension_point_disable_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY process_extension_point_disable_policy;
	if ((get_mitigation_policy(current_process, ProcessExtensionPointDisablePolicy, &process_extension_point_disable_policy, sizeof(process_extension_point_disable_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (process_extension_point_disable_policy.DisableExtensionPoints)
		report_ec(process_legacy_dll_extension_points_disabled, hreporter, dwthread_id);
	else
		report_ec(process_legacy_dll_extension_points_enabled, hreporter, dwthread_id);
	return verbose_mitig_success;
}
enum verbose_mitig_error_code report_cfg_polciy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY process_cfg_policy;
	if ((get_mitigation_policy(current_process, ProcessControlFlowGuardPolicy, &process_cfg_policy, sizeof(process_cfg_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (process_cfg_policy.EnableControlFlowGuard) {
		report_ec(process_cfg_enabled, hreporter, dwthread_id);

		if (process_cfg_policy.EnableExportSuppression)
			report_ec(process_cfg_export_functions_indirect_calls_allowed, hreporter, dwthread_id);
		else report_ec(process_cfg_export_functions_indirect_calls_disalled, hreporter, dwthread_id);
		if (process_cfg_policy.StrictMode)
			report_ec(process_cfg_strict_enabled, hreporter, dwthread_id);
		else report_ec(process_cfg_strict_disabled, hreporter, dwthread_id);
	}
	else report(process_cfg_disabled, hreporter, dwthread_id);


}
enum verbose_mitig_error_code report_process_sign_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY process_bin_sig_policy;
	if ((get_mitigation_policy(current_process, ProcessSignaturePolicy, &process_bin_sig_policy, sizeof(process_bin_sig_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (process_bin_sig_policy.MicrosoftSignedOnly)
		report_ec(process_bin_sig_policy_signed_only, hreporter, dwthread_id);
	else if (process_bin_sig_policy.StoreSignedOnly)
		report_ec(process_bin_sig_policy_signed_only, hreporter, dwthread_id);
	else if (process_bin_sig_policy.MitigationOptIn)
		report_ec(process_bin_sig_policy_whql_sign_only, hreporter, dwthread_id);
	return verbose_mitig_success;


}
enum verbose_mitig_error_code report_font_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_FONT_DISABLE_POLICY process_font_policy;
	if ((get_mitigation_policy(current_process, ProcessFontDisablePolicy, &process_font_policy, sizeof(process_font_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (process_font_policy.DisableNonSystemFonts)
		report_ec(process_system_font_only, hreporter, dwthread_id);
	else report_ec(process_arbitrary_font, hreporter, dwthread_id);
	return verbose_mitig_success;
}
enum verbose_mitig_error_code report_image_load_policy(HANDLE current_process, HANDLE hreporter, DWORD dwthread_id) {
	PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_load_policy;
	if ((get_mitigation_policy(current_process, ProcessImageLoadPolicy, &image_load_policy, sizeof(image_load_policy))) != verbose_mitig_success) {
		report_ec(process_mitigs_failed, hreporter, dwthread_id);
		return process_mitigs_failed;
	}
	if (image_load_policy.NoRemoteImages)
		report_ec(process_image_policy_no_remote_image, hreporter, dwthread_id);
	else report_ec(process_image_policy_remote_image_allowed, hreporter, dwthread_id);
	if (image_load_policy.AuditNoRemoteImages)
		report_ec(process_image_policy_load_image_lowil_prohibited, hreporter, dwthread_id);
	else
		report_ec(process_image_policy_load_image_arbitrary_il, hreporter, dwthread_id);
	if (image_load_policy.PreferSystem32Images)
		report_ec(process_image_policy_prefer_system32_image, hreporter, dwthread_id);
	else report_ec(process_image_policy_remote_image_allowed, hreporter, dwthread_id);
	return verbose_mitig_success;

}
void update_cleanup(Pupdate_info uinfo) {
	if (uinfo->update_collection != NULL)uinfo->update_collection->lpVtbl->Release(uinfo->update_collection);
	if (uinfo->update_result != NULL)uinfo->update_result->lpVtbl->Release(uinfo->update_result);
	if (uinfo->update_searcher != NULL)uinfo->update_searcher->lpVtbl->Release(uinfo->update_searcher);
	if (uinfo->update_session != NULL)uinfo->update_session->lpVtbl->Release(uinfo->update_session);
	CoUninitialize();

}
enum verbose_mitig_error_code update_session(enum tagServerSelection* server_selection, Pupdate_info uinfo, HANDLE reporter_event, DWORD reporter_threadid) {
	HRESULT hr;
	hr = CoInitializeEx(NULL, 0);
	if (FAILED(hr)) {
		report_ec(update_failed_com_object_initialization, reporter_event, reporter_threadid);
		update_cleanup(uinfo);
		return update_failed_com_object_initialization;
	}
	hr = CoCreateInstance(&CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, &IID_IUpdateSession, (LPVOID*)& uinfo->update_session);
	if (FAILED(hr)) {
		report_ec(update_failed_com_object_initialization, reporter_event, reporter_threadid);
		update_cleanup(uinfo);

		return update_failed_com_object_initialization;
	}
	hr = uinfo->update_session->lpVtbl->CreateUpdateSearcher(uinfo->update_session, &uinfo->update_searcher);
	if (FAILED(hr)) {
		report_ec(update_failed_create_update_searcher, reporter_event, reporter_threadid);
		update_cleanup(uinfo);
		return verbose_mitig_success;
	}
	uinfo->update_searcher->lpVtbl->get_ServerSelection(uinfo->update_searcher, &server_selection);



}
enum verbose_mitig_error_code updates_inter_cleanup(Pupdate_info uinfo, BOOL error_occured) {
	if (uinfo->update_string_collection != NULL)
		uinfo->update_string_collection->lpVtbl->Release(uinfo->update_string_collection);
	if (uinfo->update_info != NULL)
		uinfo->update_string_collection->lpVtbl->Release(uinfo->update_info);
	if (error_occured == TRUE)
		update_cleanup(uinfo);
}
enum verbose_mitig_error_code report_updates(enum tagServerSelection* server_selection, Pupdate_info uinfo, HANDLE hreporter, DWORD threadid) {
	char* buffer1 = allocheap(1);
	char* buffer2 = allocheap(1);
	DWORD cont_size1 = 0;
	DWORD cont_size2 = 0;
	DWORD prev1 = 0;
	DWORD prev2 = 0;
	char* delimiter = "\n";
	ULONG update_count = 0;
	BOOL error_occured = TRUE;
	HRESULT hr = NULL;
	LONG kbid_count = 0;
	DWORD dwlen = 0;
	DWORD dwlen2 = 0;
	char* multibyte_string1;
	char* multibyte_string2;
	BSTR kb_id = NULL;
	BSTR upd_str = NULL;
	BSTR update_string = SysAllocString(L"IsInstalled=1 or IsHidden=1 or IsPresent=1");
	hr = uinfo->update_searcher->lpVtbl->Search(uinfo->update_searcher, update_string, &uinfo->update_result);
	SysFreeString(update_string);
	if (FAILED(hr)) {
		update_cleanup(uinfo);
		return process_mitigs_failed;
	}
	hr = uinfo->update_result->lpVtbl->get_Updates(uinfo->update_result, &uinfo->update_collection);
	if (FAILED(hr)) {
		update_cleanup(uinfo);
		return process_mitigs_failed;
	}
	hr = uinfo->update_collection->lpVtbl->get_Count(uinfo->update_collection, &update_count);
	if (FAILED(hr)) {
		update_cleanup(uinfo);
		return process_mitigs_failed;
	}
	for (LONG i = 0; i < update_count; i++) {
		uinfo->update_info = NULL;
		hr = uinfo->update_collection->lpVtbl->get_Item(uinfo->update_collection, i, &uinfo->update_info);
		if (FAILED(hr)) {
			updates_inter_cleanup(uinfo, TRUE);
			return process_mitigs_failed;
		}
		hr = uinfo->update_info->lpVtbl->get_KBArticleIDs(uinfo->update_info, &uinfo->update_string_collection);
		if (FAILED(hr)) {
			updates_inter_cleanup(uinfo, TRUE);
			return process_mitigs_failed;
		}
		kbid_count = 0;
		hr = uinfo->update_string_collection->lpVtbl->get_Count(uinfo->update_string_collection, &kbid_count);
		if (FAILED(hr)) {
			updates_inter_cleanup(uinfo, TRUE);
			return process_mitigs_failed;
		}
		for (LONG i = 0; i < kbid_count; i++) {
			hr = uinfo->update_string_collection->lpVtbl->get_Item(uinfo->update_string_collection, i, &kb_id);
			if (FAILED(hr)) {

				updates_inter_cleanup(uinfo, TRUE);
				return process_mitigs_failed;
			}
			dwlen = wide2ascii(kb_id, NULL, dwlen);
			multibyte_string1 = allocheap(dwlen * sizeof(WCHAR) + 1);
			ZeroMemory(multibyte_string1, dwlen * sizeof(WCHAR) + 1);
			wide2ascii(kb_id, multibyte_string1, dwlen);
			dwlen = 0;
			prev1 = cont_size1;
			cont_size1 += strlen(multibyte_string1) + strlen(delimiter) + 1;
			buffer1 = reallocheap(buffer1, cont_size1);

			strcat(buffer1, multibyte_string1);
			strcat(buffer1, delimiter);
			/*OutputDebugStringA(multibyte_string1);*/


			freeheap(multibyte_string1);
			SysFreeString(kb_id);
		}
		hr = uinfo->update_info->lpVtbl->get_Title(uinfo->update_info, &upd_str);
		if (FAILED(hr)) {
			updates_inter_cleanup(uinfo, TRUE);
			return process_mitigs_failed;

		}
		dwlen2 = wide2ascii(upd_str, NULL, dwlen2);
		multibyte_string2 = allocheap(dwlen2 * sizeof(WCHAR) + 1);
		ZeroMemory(multibyte_string2, dwlen2 * sizeof(WCHAR) + 1);
		wide2ascii(upd_str, multibyte_string2, dwlen2);
		cont_size2 += strlen(multibyte_string2) + strlen(delimiter) + 1;
		buffer2 = reallocheap(buffer2, cont_size2);
		strcat(buffer2, multibyte_string2);
		strcat(buffer2, delimiter);
		/*OutputDebugStringA(multibyte_string2);
		*/
		/*
		report(hreporter, threadid, multibyte_string2);*/
		freeheap(multibyte_string2);
		SysFreeString(upd_str);
	}
	updates_inter_cleanup(uinfo, FALSE);
	update_cleanup(uinfo);
	report(hreporter, threadid, buffer1);
	report(hreporter, threadid, buffer2);
	
	freeheap(buffer2);
	freeheap(buffer1);
	return verbose_mitig_success;

}


