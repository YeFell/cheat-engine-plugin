#pragma once

class KHack;
class NtFun
{
public:
	NtFun(KHack* kh);
	~NtFun();
public:

	NTSTATUS ReadProcessMemory(HANDLE pid, ptr addr, ptr buffer, u64 size, u64* lpNumberOfBytesRead);
	NTSTATUS WriteProcessMemory(HANDLE pid, ptr addr, ptr buffer, u64 nSize, u64* lpNumberOfBytesWritten);
	NTSTATUS AllocateVirtualMemory(HANDLE pid, ptr* addr, u32 ZeroBits, u64* RegionSize, u32 AllocationType, u32 Protect);
	NTSTATUS FreeVirtualMemory(HANDLE pid, ptr* addr, u64* RegionSize, u32 FreeType);
	NTSTATUS QueryVirtualMemory(HANDLE pid, ptr addr, MEMORY_INFORMATION_CLASS InfoClass, ptr* info, u64 size, u64* returnlenghut);
	NTSTATUS FlushVirtualMemory(HANDLE pid, ptr* addr, u64* size, PIO_STATUS_BLOCK IoStatus);
	NTSTATUS LockVirtualMemory(HANDLE pid, ptr* addr, u32* LockSize, u32 LockType);
	NTSTATUS UnlockVirtualMemory(HANDLE pid, ptr* addr, u32* LockSize, u32 LockType);
	NTSTATUS ProtectVirtualMemory(HANDLE pid, ptr* addr, u32* ProtectSize, u32 NewProtect, u32* OldProtect);
	NTSTATUS ResumeProcess(HANDLE pid);
	NTSTATUS ResumeProcess(PEPROCESS process);
	NTSTATUS SuspendProcess(HANDLE pid);
	NTSTATUS SuspendProcess(PEPROCESS process);
	NTSTATUS QuerySystemInformationEx(u32 SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	NTSTATUS QueryInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	NTSTATUS SetInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
	NTSTATUS FlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG FlushSize);


	NTSTATUS SetContextThread(HANDLE ThreadId, PCONTEXT Context);
	NTSTATUS SetContextThread(PETHREAD thread, PCONTEXT Context);

	NTSTATUS GetContextThread(HANDLE ThreadId, PCONTEXT Context);
	NTSTATUS GetContextThread(PETHREAD thread, PCONTEXT Context);

	NTSTATUS SuspendThread(HANDLE ThreadId, u32* PreviousSuspendCount);
	NTSTATUS ResumeThread(HANDLE ThreadId, u32* PreviousSuspendCount);

	NTSTATUS QueryInformationThread(HANDLE ThreadId, THREADINFOCLASS ThreadInformationClass, ptr ThreadInformation, u32 ThreadInformationLength, u32* ReturnLength);

	NTSTATUS QuerySystemInformation(u32 SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	NTSTATUS SetInformationThread(HANDLE ThreadId, THREADINFOCLASS ThreadInformationClass, ptr ThreadInformation, u32 ThreadInformationLength);

	NTSTATUS OpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

	NTSTATUS OpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

	static PETHREAD GetNextThread(IN PEPROCESS Process, IN PETHREAD thread);

	NTSTATUS CreateThread(HANDLE handle, PVOID StartAddress, PVOID ThreadParameter);

	NTSTATUS RipExecutionCode(HANDLE handle, PVOID Address,PVOID  Parameter,PCONTEXT context);

	NTSTATUS RipExecutionCodeSetRip(PEPROCESS process, PVOID Address, PVOID Parameter, PVOID shellCodeBase, PCONTEXT context );
private:
	SYMBOL_FUNCTION_ADDR*		symbol;
	KHack*						g_kh;
};

