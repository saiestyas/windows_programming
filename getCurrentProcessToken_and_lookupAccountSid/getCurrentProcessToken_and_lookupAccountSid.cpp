// get_tocken_information_poc.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Header.h"

using namespace std;

HANDLE openProcess(HANDLE hprocess, DWORD desired_access) {

    HANDLE htoken;

    if (!OpenProcessToken(hprocess, desired_access, &htoken)) {
        wcout << L"Error opening current proces token" << to_wstring(GetLastError()) << endl;
        exit(1);
    }
    return htoken;
}

TOKEN_USER* get_token_info(HANDLE htoken) {

    DWORD token_size;

    //get the TokenUser structure size
    if (!GetTokenInformation(htoken, TokenUser, NULL, 0, &token_size)) {
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER) {
            wcout << L"Error in: GetTokenInformation, TokenUser length: " << err << endl;
            exit(1);
        }
    }

    //Getting info
    TOKEN_USER* token_information = (TOKEN_USER*)malloc(token_size);

    if (!GetTokenInformation(htoken, TokenUser, token_information, token_size, &token_size)) {
        wcout << L"Error in: GetTokenInformation,failure getting info:  " << to_wstring(GetLastError()) << endl;
        exit(1);
    }

    return token_information;
}

wstring userSid_toStringSid(PSID token_information) {

    //Get User SID
    wchar_t* string_sid;

    if (!ConvertSidToStringSid(token_information, &string_sid)) {
        wcout << L"Error in: ConvertSidToStringSid,failure getting the conversion:  " << to_wstring(GetLastError()) << endl;
        exit(1);
    }

    return (wstring)string_sid;
}

vector<wstring> get_user_domain_from_stringSid(TOKEN_USER* token_information) {
    SID_NAME_USE sid_type;
    DWORD name_size = 0;
    DWORD domain_size = 0;
    LookupAccountSid(
        NULL, //lpSystemName
        token_information->User.Sid, //Sid
        NULL, //Name
        &name_size, //cchName
        NULL, //ReferencedDomain
        &domain_size, //cchReferencedDomain
        &sid_type //peUse
    );


    wchar_t* name_buffer = (wchar_t*)malloc(name_size * sizeof(wchar_t));
    wchar_t* domain_buffer = (wchar_t*)malloc(domain_size * sizeof(wchar_t));
    vector<wstring> arr = {};

    if (name_buffer == nullptr || domain_buffer == nullptr) {
        wcout << L"Error, memory could not be assigned to the buffers" << endl;   
    } 
    else {
        LookupAccountSid(
            NULL, //lpSystemName
            token_information->User.Sid, //Sid
            name_buffer, //Name
            &name_size, //cchName
            domain_buffer, //ReferencedDomain
            &domain_size, //cchReferencedDomain
            &sid_type
        );

        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER) {
            wcout << L"Error: LookupAccountSid failure" << err << endl;
            exit(1);
        }

         arr = { wstring(name_buffer), wstring(domain_buffer) };

        free(name_buffer);
        free(domain_buffer);
        }

    return arr;
}


int main() {
    //GetCurrentProcess, OpenProcessTocken, GetTockenInformation, ConvertSidToStringSid, LookupAccountSid

    HANDLE hCurrentProcess;

    //[*] Obtain current process handle
    hCurrentProcess = GetCurrentProcess();
    wcout << "[*] Current process handle obtained." << endl;

    //[*] Obtain token handle from the current process => QUERY MODE
    HANDLE htoken = openProcess(hCurrentProcess, TOKEN_QUERY);
    wcout << "[*] Token could be retrieved." << endl;

    ////[*] Obtain token information structure
    TOKEN_USER* token_information = get_token_info(htoken);
    wcout << L"[*] Raw Token user -  before convertStringSidToSid: " << token_information->User.Sid << endl;

    wstring str_sid = userSid_toStringSid(token_information->User.Sid);
    wcout << "[*] User SID: " << str_sid << endl;

    //[*] Obtian process username and domain
    vector<wstring> user_domain = get_user_domain_from_stringSid(token_information);
    wcout << L"[*] Process name account: " << user_domain[0] << endl;
    wcout << L"[*] Process domain account: " << user_domain[1] << endl;

    //memory frees
    CloseHandle(htoken);
    CloseHandle(hCurrentProcess);
    free(token_information);

    return 1;


}


