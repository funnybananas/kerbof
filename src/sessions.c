#include "sessions.h"

NTSTATUS GetLogonSessionData(LUID luid, LOGON_SESSION_DATA* data) {
    LOGON_SESSION_DATA sessionData;
    PSECURITY_LOGON_SESSION_DATA logonData = NULL;
    NTSTATUS status;
    if (luid.LowPart != 0) {
        status = SECUR32$LsaGetLogonSessionData(&luid, &logonData);
        if (NT_SUCCESS(status)) {
            sessionData.sessionData = MSVCRT$calloc(1, sizeof(*sessionData.sessionData));
            if (sessionData.sessionData != NULL) {
                sessionData.sessionCount = 1;
                sessionData.sessionData[0] = logonData;
                *data = sessionData;
            } else {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    } else {
        ULONG logonSessionCount;
        PLUID logonSessionList;
        status = SECUR32$LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList);
        if (NT_SUCCESS(status)) {
            sessionData.sessionData = MSVCRT$calloc(logonSessionCount, sizeof(*sessionData.sessionData));
            if (sessionData.sessionData != NULL) {
                sessionData.sessionCount = logonSessionCount;
                for (int i = 0; i < logonSessionCount; i++) {
                    LUID luid = logonSessionList[i];
                    status = SECUR32$LsaGetLogonSessionData(&luid, &logonData);
                    if (NT_SUCCESS(status)) {
                        sessionData.sessionData[i] = logonData;
                    } else {
                        sessionData.sessionData[i] = NULL;
                    }
                }
                SECUR32$LsaFreeReturnBuffer(logonSessionList);
                *data = sessionData;
            } else {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    }
    return status;
}


void execute_sessions(HANDLE hToken, LUID luid, BOOL currentLuid) {
    // IsHighIntregrity breaks it
    BOOL highIntegrity = IsHighIntegrity(hToken);
//    BOOL highIntegrity = TRUE;
    if (!highIntegrity && !currentLuid) {
        PRINT(dispatch, "[!] Not in high integrity.\n");
        return;
    }
    HANDLE hLsa;
    NTSTATUS status = GetLsaHandle(hToken, highIntegrity, &hLsa);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] GetLsaHandle %ld\n", status);
        return;
    }
    ULONG authPackage;
    LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] LsaLookupAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }

    LOGON_SESSION_DATA sessionData;
    status = GetLogonSessionData(luid, &sessionData);

    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] GetLogonSessionData: %ld", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
    cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
//{ something from here...
    for (int i = 0; i < sessionData.sessionCount; i++) {
//        if (sessionData.sessionData[i] == NULL) {
//            continue;
//        }
//        PrintLogonSessionData(dispatch, (*sessionData.sessionData[i]));
         WCHAR* sid = NULL;
         ADVAPI32$ConvertSidToStringSidW(sessionData.sessionData[i]->Sid, &sid);
         SYSTEMTIME logon_utc = ConvertToSystemtime(sessionData.sessionData[i]->LogonTime);

         BeaconPrintf(CALLBACK_OUTPUT,
	     "\nUsername             : %s\n"
	     "Domain               : %s\n"
	     "LogonId              : %lx:0x%lx\n"
	     "UserSID              : %s\n"
	     "AuthPackage          : %s\n"
	     "LogonTime            : %d/%d/%d %d:%d:%d\n"
	     "LogonServer          : %s\n"
	     "LogonServerDNSDomain : %s\n"
         "UserPrincipalName    : %s\n",
	     GetNarrowStringFromUnicode(sessionData.sessionData[i]->UserName),
	     GetNarrowStringFromUnicode(sessionData.sessionData[i]->LogonDomain),
	     sessionData.sessionData[i]->LogonId.HighPart, sessionData.sessionData[i]->LogonId.LowPart,
	     GetNarrowString(sid),
	     GetNarrowStringFromUnicode(sessionData.sessionData[i]->AuthenticationPackage),
	     logon_utc.wMonth, logon_utc.wDay, logon_utc.wYear, logon_utc.wHour, logon_utc.wMinute, logon_utc.wSecond,
	     GetNarrowStringFromUnicode(sessionData.sessionData[i]->LogonServer),
	     GetNarrowStringFromUnicode(sessionData.sessionData[i]->DnsDomainName),
	     GetNarrowStringFromUnicode(sessionData.sessionData[i]->Upn)
	     );

        if (highIntegrity) {
            cacheRequest.LogonId = sessionData.sessionData[i]->LogonId;
        } else {
            cacheRequest.LogonId = (LUID){.HighPart = 0, .LowPart = 0};
        }

        SECUR32$LsaFreeReturnBuffer(sessionData.sessionData[i]);
        KERB_QUERY_TKT_CACHE_EX_RESPONSE* cacheResponse = NULL;
//    BOOL highIntegrity = IsHighIntegrity(hToken);
//    if (!highIntegrity && !currentLuid) {
//        PRINT(dispatch, "[!] Not in high integrity.\n");
//        return;
//    }
//
//    LOGON_SESSION_DATA sessionData;
//    PSECURITY_LOGON_SESSION_DATA data;
//    NTSTATUS status = GetLogonSessionData(luid, &sessionData);
//
//    if (NT_SUCCESS(status)) {
//        for (int i = 0; i < sessionData.sessionCount; i++) {
//            data = sessionData.sessionData[i];
//            if (data != NULL) {
//                PrintLogonSessionData(*data);
//                if (i != sessionData.sessionCount - 1) {
//                    PRINT(dispatch, "\n\n");
//                }
//                SECUR32$LsaFreeReturnBuffer(data);
//            }
//        }
//        MSVCRT$free(sessionData.sessionData);
//    } else {
//        PRINT(dispatch, "[!] execute_sessions GetLogonSessionData: %ld", status);
//    }
}

//char* GetLogonTypeString(ULONG uLogonType) {
//    char* logonType = NULL;
//    switch (uLogonType) {
//        case LOGON32_LOGON_INTERACTIVE:
//            logonType = "Interactive";
//            break;
//        case LOGON32_LOGON_NETWORK:
//            logonType = "Network";
//            break;
//        case LOGON32_LOGON_BATCH:
//            logonType = "Batch";
//            break;
//        case LOGON32_LOGON_SERVICE:
//            logonType = "Service";
//            break;
//        case LOGON32_LOGON_UNLOCK:
//            logonType = "Unlock";
//            break;
//        case LOGON32_LOGON_NETWORK_CLEARTEXT:
//            logonType = "Network_Cleartext";
//            break;
//        case LOGON32_LOGON_NEW_CREDENTIALS:
//            logonType = "New_Credentials";
//            break;
//        default:
//            logonType = "(0)";
//            break;
//    }
//    return logonType;
//}
//

//void PrintLogonSessionData(SECURITY_LOGON_SESSION_DATA data) {
//    BeaconPrintf(CALLBACK_OUTPUT, "sessions.c:PrintLogonSessionData");
//    WCHAR* sid = NULL;
//    ADVAPI32$ConvertSidToStringSidW(sessionData.sessionData[i]->Sid, &sid);
//    SYSTEMTIME logon_utc = ConvertToSystemtime(sessionData.sessionData[i]->LogonTime);
//   BeaconPrintf(CALLBACK_OUTPUT,
//       "\nUsername             : %s\n",
//       "Domain               : %s\n"
//       "LogonId              : %lx:0x%lx\n"
//       "UserSID              : %s\n"
//       "AuthPackage          : %s\n"
//       "LogonTime            : %d/%d/%d %d:%d:%d\n"
//       "LogonServer          : %s\n"
//       "LogonServerDNSDomain : %s\n"
//       "UserPrincipalName    : %s\n",
//       GetNarrowStringFromUnicode(data.UserName)
//       GetNarrowStringFromUnicode(sessionData.sessionData[i]->LogonDomain),
//       sessionData.sessionData[i]->LogonId.HighPart, sessionData.sessionData[i]->LogonId.LowPart,
//       GetNarrowString(sid),
//       GetNarrowStringFromUnicode(sessionData.sessionData[i]->AuthenticationPackage),
//       logon_utc.wMonth, logon_utc.wDay, logon_utc.wYear, logon_utc.wHour, logon_utc.wMinute, logon_utc.wSecond,
//       GetNarrowStringFromUnicode(sessionData.sessionData[i]->LogonServer),
//       GetNarrowStringFromUnicode(sessionData.sessionData[i]->DnsDomainName),
//       GetNarrowStringFromUnicode(sessionData.sessionData[i]->Upn)
//        );

//    WCHAR* sid = NULL;
//
//    PRINT(dispatch, "UserName                : %.*s\n", data.UserName.Length / (int)sizeof(char),
//          GetNarrowString(data.UserName.Buffer));
//    PRINT(dispatch, "Domain                  : %.*s\n", data.LogonDomain.Length / (int)sizeof(char),
//          GetNarrowString(data.LogonDomain.Buffer));
//    PRINT(dispatch, "LogonId                 : %lx:0x%lx\n", data.LogonId.HighPart, data.LogonId.LowPart);
//    PRINT(dispatch, "Session                 : %ld\n", data.Session);
//    if (ADVAPI32$ConvertSidToStringSidW(data.Sid, &sid)) {
//        PRINT(dispatch, "UserSID                 : %s\n", GetNarrowString(sid));
//    } else {
//        PRINT(dispatch, "UserSID                 : -\n");
//    }
//    PRINT(dispatch, "Authentication package  : %.*s\n", data.AuthenticationPackage.Length / (int)sizeof(char),
//          GetNarrowString(data.AuthenticationPackage.Buffer));
//    char* logonType = GetLogonTypeString(data.LogonType);
//    BeaconPrintf(CALLBACK_OUTPUT, "LogonType               : %s\n", dispatch, logonType);
//    SYSTEMTIME st_utc = ConvertToSystemtime(data.LogonTime);
//    PRINT(dispatch, "LogonTime (UTC)         : %d/%d/%d %d:%d:%d\n", st_utc.wDay, st_utc.wMonth, st_utc.wYear,
//          st_utc.wHour, st_utc.wMinute, st_utc.wSecond);
//    PRINT(dispatch, "LogonServer             : %.*s\n", data.LogonServer.Length / (int)sizeof(char),
//          GetNarrowString(data.LogonServer.Buffer));
//    PRINT(dispatch, "LogonServerDNSDomain    : %.*s\n", data.DnsDomainName.Length / (int)sizeof(char),
//          GetNarrowString(data.DnsDomainName.Buffer));
//    PRINT(dispatch, "UserPrincipalName       : %.*s\n", data.Upn.Length / (int)sizeof(char),
//          GetNarrowString(data.Upn.Buffer));
}
