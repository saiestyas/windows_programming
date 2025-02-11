// process_enumeration.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>
using namespace std;

int main(){
    //CreateTool32Snapshoot, Process32First, Process32Next
    HANDLE h_snap;

    h_snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, //Include all processes in the system
        NULL
    );

    if (h_snap == INVALID_HANDLE_VALUE) {
        wcout << L"Invalid handle value, error code: " << to_wstring(GetLastError()) << endl;
        return 1;
    }
    
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(h_snap,&process_entry)) {
        wcout << L"Proces name: " << process_entry.szExeFile;
        wcout << L" PID: " << process_entry.th32ProcessID << endl;
    }
    
    do {
        if (Process32Next(h_snap, &process_entry)) {
            wcout << L"Proces name: " << process_entry.szExeFile;
            wcout << L" PID: " << process_entry.th32ProcessID << endl;
        }
    }while (GetLastError() != ERROR_NO_MORE_FILES);

    return 0;
}




