#pragma once
#include "ROPBuffer.h"

extern ULONGLONG PopGadgetsAddress;
extern ULONGLONG PushRaxAddress;

extern ULONGLONG MessageBoxAddress;
extern ULONGLONG CreateMutexAddress;
extern ULONGLONG RtlExitUserThreadAddress;

extern ULONGLONG ZwAllocateVirtualMemoryAddress;

VOID FindFunctionAddresses();

VOID BuildSimpleRop(ROPBuffer* Rop, ULONGLONG RemoteShellcode, ULONGLONG RemoteShellcodeAddress);