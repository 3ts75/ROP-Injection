#pragma once
#include <Windows.h>

class ROPBuffer {
	ULONGLONG TargetRip;
	ULONGLONG TargetRsp;
	ULONG CurrentPosition;
	ULONG DataPosition;
	ULONGLONG* Buffer;
	SIZE_T BufferSize;

public:
	ROPBuffer(ULONGLONG Rsp, SIZE_T ROPBufferEntries);
	virtual ~ROPBuffer();

	virtual ULONGLONG SetRip(ULONGLONG Address);
	virtual ULONGLONG InsertRopValue(ULONGLONG Value);
	virtual ULONGLONG InsertRopDataPointer(ULONGLONG Data);

	virtual ULONGLONG* GetBuffer();
	virtual SIZE_T GetBufferSize();
	virtual ULONGLONG GetRip();
	virtual ULONGLONG GetRsp();
};