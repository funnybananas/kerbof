#pragma once

#include <windows.h>
#include "common.h"

void execute_luid(HANDLE hToken);
LUID* GetCurrentLUID(HANDLE TokenHandle);
