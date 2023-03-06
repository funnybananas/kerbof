#pragma once

#include <windows.h>
#include "bofdefs.h"
#include "common.h"
#include "luid.h"

void execute_sessions(HANDLE hToken, LUID luid, BOOL currentLuid);
NTSTATUS GetLogonSessionData(LUID luid, LOGON_SESSION_DATA* data);
char* GetLogonTypeString(ULONG uLogonType);
void PrintLogonSessionData(SECURITY_LOGON_SESSION_DATA data);
