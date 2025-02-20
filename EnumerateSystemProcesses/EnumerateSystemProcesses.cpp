// EnumerateSystemProcesses.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Windows.h"
#include <vector>
#include <string>
#include "tlhelp32.h";
#include "sddl.h";
using namespace std;

int main() {

    wstring error;
    HANDLE h_snap;
    vector <PROCESSENTRY32> process_tree;

    //Get current process tree
    
    //Get Process snapshot
    h_snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, //Include all processes in the system
        NULL
    );

    if (h_snap == INVALID_HANDLE_VALUE) {
        error = to_wstring(GetLastError());
        wcout << L"Invalid handle value, error code: " << error << endl;
    }

    //Store processes on an array
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);


    if (Process32First(h_snap, &process_entry)) {
        process_tree.push_back(process_entry);
    }

    do {
        process_tree.push_back(process_entry);
    } while (Process32Next(h_snap, &process_entry));

    CloseHandle(h_snap);


    //Go process by process checking if the SID is equal to NT SYSTEM  SID: S-1-5-18 
    for (const auto& process : process_tree) {

        wstring pname = process.szExeFile;

        if (pname.find(L".exe") == std::wstring::npos) {
            continue; //try just .exe files
        }

        //Open each process
        HANDLE hprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.th32ProcessID);
        if (hprocess == 0) {
            continue; //process could not be opened so try next iteration
        }

        //get token process
        HANDLE htoken;
        OpenProcessToken(hprocess, TOKEN_QUERY, &htoken);

        //get token information
        DWORD token_size;

        //get the TokenUser structure size
        GetTokenInformation(htoken, TokenUser, NULL, 0, &token_size);
        TOKEN_USER* token_information = (TOKEN_USER*)malloc(token_size);

        //Getting Token info
        if (!GetTokenInformation(htoken, TokenUser, token_information, token_size, &token_size)) {
            wstring err = to_wstring(GetLastError());
            wcout << L"Error in: 2-GetTokenInformation,failure getting info:  " << err << endl;
        }

        //convert userSid to String Sid
        wchar_t* string_sid;

        if (!ConvertSidToStringSid(token_information->User.Sid, &string_sid)) {
            wstring err = to_wstring(GetLastError());
            wcout << L"Error in: ConvertSidToStringSid,failure getting the conversion:  " << err << endl;
            continue;
        }

        //check if the obtained sid corresponds to NT SYSTEM
        wstring sid = string_sid;
        if (sid.find(L"S-1-5-18") != std::wstring::npos) {
            wcout << L"[*] " << process.szExeFile << L" PID: " << process.th32ProcessID << endl;
        }
        
    } //for loop end
    return 0;



}
