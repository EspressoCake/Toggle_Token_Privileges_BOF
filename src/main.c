#include <windows.h>
#include "beacon.h"
#include "syscalls.h"
#include "api_and_constants.h"

#define SE_CREATE_TOKEN_NAME_W                         L"SeCreateTokenPrivilege"
#define SE_ASSIGNPRIMARYTOKEN_NAME_W                   L"SeAssignPrimaryTokenPrivilege"
#define SE_LOCK_MEMORY_NAME_W                          L"SeLockMemoryPrivilege"
#define SE_INCREASE_QUOTA_NAME_W                       L"SeIncreaseQuotaPrivilege"
#define SE_UNSOLICITED_INPUT_NAME_W                    L"SeUnsolicitedInputPrivilege"
#define SE_MACHINE_ACCOUNT_NAME_W                      L"SeMachineAccountPrivilege"
#define SE_TCB_NAME_W                                  L"SeTcbPrivilege"
#define SE_SECURITY_NAME_W                             L"SeSecurityPrivilege"
#define SE_TAKE_OWNERSHIP_NAME_W                       L"SeTakeOwnershipPrivilege"
#define SE_LOAD_DRIVER_NAME_W                          L"SeLoadDriverPrivilege"
#define SE_SYSTEM_PROFILE_NAME_W                       L"SeSystemProfilePrivilege"
#define SE_SYSTEMTIME_NAME_W                           L"SeSystemtimePrivilege"
#define SE_PROF_SINGLE_PROCESS_NAME_W                  L"SeProfileSingleProcessPrivilege"
#define SE_INC_BASE_PRIORITY_NAME_W                    L"SeIncreaseBasePriorityPrivilege"
#define SE_CREATE_PAGEFILE_NAME_W                      L"SeCreatePagefilePrivilege"
#define SE_CREATE_PERMANENT_NAME_W                     L"SeCreatePermanentPrivilege"
#define SE_BACKUP_NAME_W                               L"SeBackupPrivilege"
#define SE_RESTORE_NAME_W                              L"SeRestorePrivilege"
#define SE_SHUTDOWN_NAME_W                             L"SeShutdownPrivilege"
#define SE_DEBUG_NAME_W                                L"SeDebugPrivilege"
#define SE_AUDIT_NAME_W                                L"SeAuditPrivilege"
#define SE_SYSTEM_ENVIRONMENT_NAME_W                   L"SeSystemEnvironmentPrivilege"
#define SE_CHANGE_NOTIFY_NAME_W                        L"SeChangeNotifyPrivilege"
#define SE_REMOTE_SHUTDOWN_NAME_W                      L"SeRemoteShutdownPrivilege"
#define SE_UNDOCK_NAME_W                               L"SeUndockPrivilege"
#define SE_SYNC_AGENT_NAME_W                           L"SeSyncAgentPrivilege"
#define SE_ENABLE_DELEGATION_NAME_W                    L"SeEnableDelegationPrivilege"
#define SE_MANAGE_VOLUME_NAME_W                        L"SeManageVolumePrivilege"
#define SE_IMPERSONATE_NAME_W                          L"SeImpersonatePrivilege"
#define SE_CREATE_GLOBAL_NAME_W                        L"SeCreateGlobalPrivilege"
#define SE_TRUSTED_CREDMAN_ACCESS_NAME_W               L"SeTrustedCredManAccessPrivilege"
#define SE_RELABEL_NAME_W                              L"SeRelabelPrivilege"
#define SE_INC_WORKING_SET_NAME_W                      L"SeIncreaseWorkingSetPrivilege"
#define SE_TIME_ZONE_NAME_W                            L"SeTimeZonePrivilege"
#define SE_CREATE_SYMBOLIC_LINK_NAME_W                 L"SeCreateSymbolicLinkPrivilege"
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME_W    L"SeDelegateSessionUserImpersonatePrivilege"

#define AUTHOR_METADATA                                L"Authors:\n\t@the_bit_diddler\n\t@hackersoup"

void enable(char *args, int len) {
    DWORD privilegeValue;
    LPCWSTR lpPrivilege;
    datap parser;

    BeaconDataParse(&parser, args, len);
    privilegeValue = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "%ls\n", (wchar_t*)AUTHOR_METADATA);

    if (!BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "You are not currently in an administrative session. Come again later!\n");
        return;
    }

    if (privilegeValue == 1) {
        lpPrivilege = SE_CREATE_TOKEN_NAME_W;
    }

    if (privilegeValue == 2) {
        lpPrivilege = SE_ASSIGNPRIMARYTOKEN_NAME_W;
    }

    if (privilegeValue == 3) {
        lpPrivilege = SE_LOCK_MEMORY_NAME_W;
    }

    if (privilegeValue == 4) {
        lpPrivilege = SE_INCREASE_QUOTA_NAME_W;
    }

    if (privilegeValue == 5) {
        lpPrivilege = SE_UNSOLICITED_INPUT_NAME_W;
    }

    if (privilegeValue == 6) {
        lpPrivilege = SE_MACHINE_ACCOUNT_NAME_W;
    }

    if (privilegeValue == 7) {
        lpPrivilege = SE_TCB_NAME_W;
    }

    if (privilegeValue == 8) {
        lpPrivilege = SE_SECURITY_NAME_W;
    }

    if (privilegeValue == 9) {
        lpPrivilege = SE_TAKE_OWNERSHIP_NAME_W;
    }

    if (privilegeValue == 10) {
        lpPrivilege = SE_LOAD_DRIVER_NAME_W;
    }

    if (privilegeValue == 11) {
        lpPrivilege = SE_SYSTEM_PROFILE_NAME_W;
    }

    if (privilegeValue == 12) {
        lpPrivilege = SE_SYSTEMTIME_NAME_W;
    }

    if (privilegeValue == 13) {
        lpPrivilege = SE_PROF_SINGLE_PROCESS_NAME_W;
    }

    if (privilegeValue == 14) {
        lpPrivilege = SE_INC_BASE_PRIORITY_NAME_W;
    }

    if (privilegeValue == 15) {
        lpPrivilege = SE_CREATE_PAGEFILE_NAME_W;
    }

    if (privilegeValue == 16) {
        lpPrivilege = SE_CREATE_PERMANENT_NAME_W;
    }

    if (privilegeValue == 17) {
        lpPrivilege = SE_BACKUP_NAME_W;
    }

    if (privilegeValue == 18) {
        lpPrivilege = SE_RESTORE_NAME_W;
    }

    if (privilegeValue == 19) {
        lpPrivilege = SE_SHUTDOWN_NAME_W;
    }

    if (privilegeValue == 20) {
        lpPrivilege = SE_DEBUG_NAME_W;
    }

    if (privilegeValue == 21) {
        lpPrivilege = SE_AUDIT_NAME_W;
    }

    if (privilegeValue == 22) {
        lpPrivilege = SE_SYSTEM_ENVIRONMENT_NAME_W;
    }

    if (privilegeValue == 23) {
        lpPrivilege = SE_CHANGE_NOTIFY_NAME_W;
    }

    if (privilegeValue == 24) {
        lpPrivilege = SE_REMOTE_SHUTDOWN_NAME_W;
    }

    if (privilegeValue == 25) {
        lpPrivilege = SE_UNDOCK_NAME_W;
    }

    if (privilegeValue == 26) {
        lpPrivilege = SE_SYNC_AGENT_NAME_W;
    }

    if (privilegeValue == 27) {
        lpPrivilege = SE_ENABLE_DELEGATION_NAME_W;
    }

    if (privilegeValue == 28) {
        lpPrivilege = SE_MANAGE_VOLUME_NAME_W;
    }

    if (privilegeValue == 29) {
        lpPrivilege = SE_IMPERSONATE_NAME_W;
    }

    if (privilegeValue == 30) {
        lpPrivilege = SE_CREATE_GLOBAL_NAME_W;
    }

    if (privilegeValue == 31) {
        lpPrivilege = SE_TRUSTED_CREDMAN_ACCESS_NAME_W;
    }

    if (privilegeValue == 32) {
        lpPrivilege = SE_RELABEL_NAME_W;
    }

    if (privilegeValue == 33) {
        lpPrivilege = SE_INC_WORKING_SET_NAME_W;
    }

    if (privilegeValue == 34) {
        lpPrivilege = SE_TIME_ZONE_NAME_W;
    }

    if (privilegeValue == 35) {
        lpPrivilege = SE_CREATE_SYMBOLIC_LINK_NAME_W;
    }

    if (privilegeValue == 36) {
        lpPrivilege = SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME_W;
    }
        
    
    BeaconPrintf(CALLBACK_OUTPUT, "Attempting to acquire privilege: %ls\n", (wchar_t*)lpPrivilege);
    
    // Credit: @anthemtotheego
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);

    if(status != STATUS_SUCCESS){
    	BeaconPrintf(CALLBACK_ERROR, "Failed to open process token. :(\n");
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!ADVAPI32$LookupPrivilegeValueW(NULL, lpPrivilege, &tkp.Privileges[0].Luid)) {
		NtClose(hToken);
	}

    status = NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    if (status != STATUS_SUCCESS){
    	BeaconPrintf(CALLBACK_ERROR, "Failed to adjust process token with desired privilege: %ls\t:(\n", (wchar_t*)lpPrivilege);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Enjoy your new privileges: %ls\n", (wchar_t*)lpPrivilege);
    }

    NtClose(hToken);
}


void disable(char *args, int len) {
    DWORD privilegeValue;
    LPCWSTR lpPrivilege;
    datap parser;

    BeaconDataParse(&parser, args, len);
    privilegeValue = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "%ls\n", (wchar_t*)AUTHOR_METADATA);

    if (!BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "You are not currently in an administrative session. Come again later!\n");
        return;
    }

    if (privilegeValue == 1) {
        lpPrivilege = SE_CREATE_TOKEN_NAME_W;
    }

    if (privilegeValue == 2) {
        lpPrivilege = SE_ASSIGNPRIMARYTOKEN_NAME_W;
    }

    if (privilegeValue == 3) {
        lpPrivilege = SE_LOCK_MEMORY_NAME_W;
    }

    if (privilegeValue == 4) {
        lpPrivilege = SE_INCREASE_QUOTA_NAME_W;
    }

    if (privilegeValue == 5) {
        lpPrivilege = SE_UNSOLICITED_INPUT_NAME_W;
    }

    if (privilegeValue == 6) {
        lpPrivilege = SE_MACHINE_ACCOUNT_NAME_W;
    }

    if (privilegeValue == 7) {
        lpPrivilege = SE_TCB_NAME_W;
    }

    if (privilegeValue == 8) {
        lpPrivilege = SE_SECURITY_NAME_W;
    }

    if (privilegeValue == 9) {
        lpPrivilege = SE_TAKE_OWNERSHIP_NAME_W;
    }

    if (privilegeValue == 10) {
        lpPrivilege = SE_LOAD_DRIVER_NAME_W;
    }

    if (privilegeValue == 11) {
        lpPrivilege = SE_SYSTEM_PROFILE_NAME_W;
    }

    if (privilegeValue == 12) {
        lpPrivilege = SE_SYSTEMTIME_NAME_W;
    }

    if (privilegeValue == 13) {
        lpPrivilege = SE_PROF_SINGLE_PROCESS_NAME_W;
    }

    if (privilegeValue == 14) {
        lpPrivilege = SE_INC_BASE_PRIORITY_NAME_W;
    }

    if (privilegeValue == 15) {
        lpPrivilege = SE_CREATE_PAGEFILE_NAME_W;
    }

    if (privilegeValue == 16) {
        lpPrivilege = SE_CREATE_PERMANENT_NAME_W;
    }

    if (privilegeValue == 17) {
        lpPrivilege = SE_BACKUP_NAME_W;
    }

    if (privilegeValue == 18) {
        lpPrivilege = SE_RESTORE_NAME_W;
    }

    if (privilegeValue == 19) {
        lpPrivilege = SE_SHUTDOWN_NAME_W;
    }

    if (privilegeValue == 20) {
        lpPrivilege = SE_DEBUG_NAME_W;
    }

    if (privilegeValue == 21) {
        lpPrivilege = SE_AUDIT_NAME_W;
    }

    if (privilegeValue == 22) {
        lpPrivilege = SE_SYSTEM_ENVIRONMENT_NAME_W;
    }

    if (privilegeValue == 23) {
        lpPrivilege = SE_CHANGE_NOTIFY_NAME_W;
    }

    if (privilegeValue == 24) {
        lpPrivilege = SE_REMOTE_SHUTDOWN_NAME_W;
    }

    if (privilegeValue == 25) {
        lpPrivilege = SE_UNDOCK_NAME_W;
    }

    if (privilegeValue == 26) {
        lpPrivilege = SE_SYNC_AGENT_NAME_W;
    }

    if (privilegeValue == 27) {
        lpPrivilege = SE_ENABLE_DELEGATION_NAME_W;
    }

    if (privilegeValue == 28) {
        lpPrivilege = SE_MANAGE_VOLUME_NAME_W;
    }

    if (privilegeValue == 29) {
        lpPrivilege = SE_IMPERSONATE_NAME_W;
    }

    if (privilegeValue == 30) {
        lpPrivilege = SE_CREATE_GLOBAL_NAME_W;
    }

    if (privilegeValue == 31) {
        lpPrivilege = SE_TRUSTED_CREDMAN_ACCESS_NAME_W;
    }

    if (privilegeValue == 32) {
        lpPrivilege = SE_RELABEL_NAME_W;
    }

    if (privilegeValue == 33) {
        lpPrivilege = SE_INC_WORKING_SET_NAME_W;
    }

    if (privilegeValue == 34) {
        lpPrivilege = SE_TIME_ZONE_NAME_W;
    }

    if (privilegeValue == 35) {
        lpPrivilege = SE_CREATE_SYMBOLIC_LINK_NAME_W;
    }

    if (privilegeValue == 36) {
        lpPrivilege = SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME_W;
    }
        
    
    BeaconPrintf(CALLBACK_OUTPUT, "Attempting to revoke privilege: %ls\n", (wchar_t*)lpPrivilege);
    
    // Credit: @anthemtotheego
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);

    if(status != STATUS_SUCCESS){
    	BeaconPrintf(CALLBACK_ERROR, "Failed to open process token. :(\n");
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = NULL;

	if (!ADVAPI32$LookupPrivilegeValueW(NULL, lpPrivilege, &tkp.Privileges[0].Luid)) {
		NtClose(hToken);
	}

    status = NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    if (status != STATUS_SUCCESS){
    	BeaconPrintf(CALLBACK_ERROR, "Failed to adjust process token with desired privilege: %ls\t:(\n", (wchar_t*)lpPrivilege);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Revoked your desired privilege: %ls\n", (wchar_t*)lpPrivilege);
    }

    NtClose(hToken);
}