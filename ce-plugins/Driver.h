#pragma once
#include "../include/PDBHelp.h"

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
	SystemFirmwareTable_Enumerate,
	SystemFirmwareTable_Get
} SYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
	ULONG                           ProviderSignature;
	SYSTEM_FIRMWARE_TABLE_ACTION    Action;
	ULONG                           TableID;
	ULONG                           TableBufferLength;
	UCHAR                           TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section; // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef NTSTATUS(*NtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*NtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*RtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);



class PDBHelp;
class Driver
{
public:
	Driver();
	~Driver();

	bool Call(PVOID Pack);
	bool Call(PPacketData packetdata);

	NTSTATUS NtCall(PVOID Pack);
	NTSTATUS NtCall(PPacketData packetdata);

	bool SendSymBol(PSYMBOL_FUNCTION_ADDR PSymbolFunctionAddr);
	bool SymbolDownloader(std::string& FileName, std::string& SymbolName);
	bool SendSymbolData();
public:
	NTSTATUS ReadProcessMemory(HANDLE pid, ptr addr, ptr buffer, u64 size, u64* lpNumberOfBytesRead);
	NTSTATUS WriteProcessMemory(HANDLE pid, ptr addr, ptr buffer, u64 nSize, u64* lpNumberOfBytesWritten);
	NTSTATUS AllocateVirtualMemory(HANDLE pid, ptr* addr, u32 ZeroBits, u64* RegionSize, u32 AllocationType, u32 Protect);
	NTSTATUS FreeVirtualMemory(HANDLE pid, ptr* addr, u64* RegionSize, u32 FreeType);
	NTSTATUS QueryVirtualMemory(HANDLE pid, ptr addr, u32 InfoClass, ptr* info, u64 size, u64* returnlenghut);
	NTSTATUS ProtectVirtualMemory(HANDLE pid, ptr* addr, u32* ProtectSize, u32 NewProtect, u32* OldProtect);

	NTSTATUS QueryInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	NTSTATUS SetInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

	NTSTATUS ResumeProcess(HANDLE pid);
	NTSTATUS SuspendProcess(HANDLE pid);

	NTSTATUS SetContextThread(HANDLE ThreadId, PCONTEXT Context);
	NTSTATUS GetContextThread(HANDLE ThreadId, PCONTEXT Context);

	NTSTATUS SuspendThread(HANDLE ThreadId, u32* PreviousSuspendCount);
	NTSTATUS ResumeThread(HANDLE ThreadId, u32* PreviousSuspendCount);

	NTSTATUS OpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);

	NTSTATUS OpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);

	NTSTATUS QuerySystemInformationEx(u32 SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	NTSTATUS QuerySystemInformation(u32 SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	NTSTATUS CreateThread(HANDLE tid, PVOID start, PVOID paramtion);

	NTSTATUS ApcExecutionCode(HANDLE handle, PVOID address, PVOID parameter);


private:
	PDBHelp* PDB;
	PVOID NtQuerySystemInformation;
	PVOID RtlAdjustPrivilege;
	PVOID NtLoadDriver;
	PVOID NtUnloadDriver;

	std::map<std::string, std::string> PDBSymName;
	
};

