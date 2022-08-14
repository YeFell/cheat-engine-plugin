#include "pch.h"
#include "../common/struct.h"

#include "Driver.h"
Driver::Driver() :
	PDB(new PDBHelp("C:\\"))
{
	auto ModBase = GetModuleHandleA("ntdll.dll");
	if (ModBase)
	{
		NtQuerySystemInformation = GetProcAddress(ModBase, "NtQuerySystemInformation");
		RtlAdjustPrivilege = GetProcAddress(ModBase, "RtlAdjustPrivilege");
		NtLoadDriver = GetProcAddress(ModBase, "NtLoadDriver");
		NtUnloadDriver = GetProcAddress(ModBase, "NtUnloadDriver");
	}
	else
	{
		NtQuerySystemInformation = 
			RtlAdjustPrivilege = 
			NtLoadDriver = 
			NtUnloadDriver = NULL;
	}
}

Driver::~Driver()
{

}

NTSTATUS Driver::NtCall(PVOID Pack)
{
	if (!NtQuerySystemInformation)
		return 0xC0000001;
	return reinterpret_cast<NTSTATUS(__stdcall*)(ULONG, PVOID, ULONG, PULONG)>(NtQuerySystemInformation)(0x4C, Pack, 0x10, NULL);
}

NTSTATUS Driver::NtCall(PPacketData packetdata)
{
	SYSTEM_FIRMWARE_TABLE_INFORMATION FIRMWARE_TABLE = { 0 };
	FIRMWARE_TABLE.ProviderSignature = DriverName;
	*(uint64_t*)(&FIRMWARE_TABLE.Action) = (ULONG64)(packetdata);

	return NtCall((PVOID)&FIRMWARE_TABLE);
}

bool Driver::Call(PVOID Pack)
{
	if (!NtQuerySystemInformation)
		return FALSE;
	return (reinterpret_cast<NTSTATUS(__stdcall*)(ULONG, PVOID, ULONG, PULONG)>(NtQuerySystemInformation)(0x4C, Pack, 0x10, NULL) >= 0) ? 1 : 0;
}

bool Driver::Call(PPacketData packetdata)
{
	SYSTEM_FIRMWARE_TABLE_INFORMATION FIRMWARE_TABLE = { 0 };
	FIRMWARE_TABLE.ProviderSignature = DriverName;
	*(uint64_t*)(&FIRMWARE_TABLE.Action) = (ULONG64)(packetdata);

	return Call((PVOID)&FIRMWARE_TABLE);
}

bool Driver::SendSymBol(PSYMBOL_FUNCTION_ADDR PSymbolFunctionAddr)
{
	PacketData packetdata = { };
	packetdata.byte = PACKETENUM::__SendSymBol;
	packetdata.u.Sym = *PSymbolFunctionAddr;
	return Call(&packetdata);
}


bool Driver::SymbolDownloader(std::string& FileName, std::string& SymbolName)
{
	const char* pdbName = 0;
	char SystemPath[MAX_PATH] = { 0 };
	std::string url;

	if (!GetSystemDirectoryA(SystemPath, MAX_PATH))
		return false;

	auto FilePath = std::string(SystemPath);

	FilePath = FilePath + "\\" + FileName;

	PDB->PEHeaderReader(&FilePath, &url);

	if (url.empty())
		return false;
	else
	{
		pdbName = strrchr(url.c_str(), '/');
		++pdbName;
		SymbolName = pdbName;

		if (!PDB->FileDownloader(SymbolName, url))
		{
			SymbolName.clear();
			ConsoleOut("Symbol Downloader Error! %s", FilePath.c_str());
			return false;
		}
	}
	return true;
}

bool Driver::SendSymbolData()
{
	std::string FileName[] = {
		"ntoskrnl.exe",
		"win32k.sys"
	};

	for (size_t i = 0; i < sizeof(FileName) / sizeof(std::string); i++)
	{
		std::string pn;
		if (!SymbolDownloader(FileName[i], pn))
			return false;
		PDBSymName[FileName[i]] = pn;
	}
	SYMBOL_FUNCTION_ADDR SymbolFuncAddr = { 0 };
	HRESULT hr = S_OK;

	for (size_t i = 0; i < sizeof(FileName) / sizeof(std::string); i++)
	{
		auto Base = PDB->GetKernelModuleBase(FileName[i]);
		if ("ntoskrnl.exe" == FileName[i] && NULL == Base)
			Base = PDB->GetKernelModuleBase(std::string("ntoskrn1.exe"));

		if (!PDB->Load(PDBSymName[FileName[i]], Base))
			return false;
	}


	SymbolFuncAddr.nt.NtOpenProcess = PDB->GetSymFuncAddr("NtOpenProcess");

	SymbolFuncAddr.nt.NtReadProcessMemory = PDB->GetSymFuncAddr("NtReadVirtualMemory");
	SymbolFuncAddr.nt.NtWriteProcessMemory = PDB->GetSymFuncAddr("NtWriteVirtualMemory");

	SymbolFuncAddr.nt.PsSuspendProcess = PDB->GetSymFuncAddr("PsSuspendProcess");
	SymbolFuncAddr.nt.PsResumeProcess = PDB->GetSymFuncAddr("PsResumeProcess");
	SymbolFuncAddr.nt.NtQuerySystemInformationEx = PDB->GetSymFuncAddr("NtQuerySystemInformationEx");
	SymbolFuncAddr.nt.NtQuerySystemInformation = PDB->GetSymFuncAddr("NtQuerySystemInformation");
	SymbolFuncAddr.nt.NtQueryInformationProcess = PDB->GetSymFuncAddr("NtQueryInformationProcess");
	SymbolFuncAddr.nt.NtSetInformationProcess = PDB->GetSymFuncAddr("NtSetInformationProcess");
	SymbolFuncAddr.nt.NtFlushInstructionCache = PDB->GetSymFuncAddr("NtFlushInstructionCache");
	SymbolFuncAddr.nt.NtQueryVirtualMemory = PDB->GetSymFuncAddr("NtQueryVirtualMemory");

	ConsoleOut("NtOpenProcess:%llX", SymbolFuncAddr.nt.NtOpenProcess);

	ConsoleOut("NtReadProcessMemory:%llX", SymbolFuncAddr.nt.NtReadProcessMemory);
	ConsoleOut("NtWriteProcessMemory:%llX", SymbolFuncAddr.nt.NtWriteProcessMemory);

	ConsoleOut("PsSuspendProcess:%llX", SymbolFuncAddr.nt.PsSuspendProcess);
	ConsoleOut("PsResumeProcess:%llX", SymbolFuncAddr.nt.PsResumeProcess);
	ConsoleOut("NtQuerySystemInformation:%llX", SymbolFuncAddr.nt.NtQuerySystemInformation);
	ConsoleOut("NtQuerySystemInformationEx:%llX", SymbolFuncAddr.nt.NtQuerySystemInformationEx);
	ConsoleOut("NtQueryInformationProcess:%llX", SymbolFuncAddr.nt.NtQueryInformationProcess);
	ConsoleOut("NtSetInformationProcess:%llX", SymbolFuncAddr.nt.NtSetInformationProcess);
	ConsoleOut("NtFlushInstructionCache:%llX", SymbolFuncAddr.nt.NtFlushInstructionCache);
	ConsoleOut("NtQueryVirtualMemory:%llX", SymbolFuncAddr.nt.NtQueryVirtualMemory);

	SymbolFuncAddr.nt.NtFlushVirtualMemory = PDB->GetSymFuncAddr("NtFlushVirtualMemory");
	SymbolFuncAddr.nt.NtLockVirtualMemory = PDB->GetSymFuncAddr("NtLockVirtualMemory");
	SymbolFuncAddr.nt.NtUnlockVirtualMemory = PDB->GetSymFuncAddr("NtUnlockVirtualMemory");
	SymbolFuncAddr.nt.NtProtectVirtualMemory = PDB->GetSymFuncAddr("NtProtectVirtualMemory");

	ConsoleOut("NtFlushVirtualMemory:%llX", SymbolFuncAddr.nt.NtFlushVirtualMemory);
	ConsoleOut("NtLockVirtualMemory:%llX", SymbolFuncAddr.nt.NtLockVirtualMemory);
	ConsoleOut("NtUnlockVirtualMemory:%llX", SymbolFuncAddr.nt.NtUnlockVirtualMemory);
	ConsoleOut("NtProtectVirtualMemory:%llX", SymbolFuncAddr.nt.NtProtectVirtualMemory);

	SymbolFuncAddr.nt.NtOpenThread = PDB->GetSymFuncAddr("NtOpenThread");
	SymbolFuncAddr.nt.NtQueryInformationThread = PDB->GetSymFuncAddr("NtQueryInformationThread");
	SymbolFuncAddr.nt.NtSetInformationThread = PDB->GetSymFuncAddr("NtSetInformationThread");
	SymbolFuncAddr.nt.PsGetContextThread = PDB->GetSymFuncAddr("PsGetContextThread");
	SymbolFuncAddr.nt.PsSetContextThread = PDB->GetSymFuncAddr("PsSetContextThread");
	SymbolFuncAddr.nt.PsResumeThread = PDB->GetSymFuncAddr("PsResumeThread");
	SymbolFuncAddr.nt.PsSuspendThread = PDB->GetSymFuncAddr("PsSuspendThread");

	ConsoleOut("NtOpenThread:%llX", SymbolFuncAddr.nt.NtOpenThread);
	ConsoleOut("NtQueryInformationThread:%llX", SymbolFuncAddr.nt.NtQueryInformationThread);
	ConsoleOut("NtSetInformationThread:%llX", SymbolFuncAddr.nt.NtSetInformationThread);
	ConsoleOut("PsGetContextThread:%llX", SymbolFuncAddr.nt.PsGetContextThread);
	ConsoleOut("PsSetContextThread:%llX", SymbolFuncAddr.nt.PsSetContextThread);
	ConsoleOut("PsResumeThread:%llX", SymbolFuncAddr.nt.PsResumeThread);
	ConsoleOut("PsSuspendThread:%llX", SymbolFuncAddr.nt.PsSuspendThread);

	SymbolFuncAddr.nt.NtWaitForSingleObject = PDB->GetSymFuncAddr("NtWaitForSingleObject");
	ConsoleOut("NtWaitForSingleObject:%llX", SymbolFuncAddr.nt.NtWaitForSingleObject);


	SymbolFuncAddr.nt.PsGetNextProcessThread = PDB->GetSymFuncAddr("PsGetNextProcessThread");
	SymbolFuncAddr.nt.KeServiceDescriptorTable = PDB->GetSymFuncAddr("KeServiceDescriptorTableShadow");

	SymbolFuncAddr.nt.NtCreateThreadEx = PDB->GetSymFuncAddr("NtCreateThreadEx");

	ConsoleOut("PsGetNextProcessThread:%llX\n", SymbolFuncAddr.nt.PsGetNextProcessThread);
	ConsoleOut("KeServiceDescriptorTable:%llX\n", SymbolFuncAddr.nt.KeServiceDescriptorTable);

	ConsoleOut("NtCreateThreadEx:%llX\n", SymbolFuncAddr.nt.NtCreateThreadEx);

	SymbolFuncAddr.ntOffset._KTHREAD_PreviousMode = PDB->GetSymTypeOffset(PDBSymName["ntoskrnl.exe"], "_KTHREAD", "PreviousMode");
	ConsoleOut("_KTHREAD.PreviousMode:0x%X\n", SymbolFuncAddr.ntOffset._KTHREAD_PreviousMode);
	return SUCCEEDED(hr) ? SendSymBol(&SymbolFuncAddr) : false;
}

NTSTATUS Driver::ReadProcessMemory(HANDLE pid, ptr addr, ptr buffer, u64 size, u64* lpNumberOfBytesRead)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__ReadMemory;
	packetdata.u.Cpm.pid = pid;
	packetdata.u.Cpm.addr = addr;
	packetdata.u.Cpm.buffer = buffer;
	packetdata.u.Cpm.size = size;
	packetdata.u.Cpm.ret_size = lpNumberOfBytesRead;
	return NtCall(&packetdata);
}

NTSTATUS Driver::WriteProcessMemory(HANDLE pid, ptr addr, ptr buffer, u64 nSize, u64* lpNumberOfBytesWritten)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__WriteMemory;
	packetdata.u.Cpm.pid = pid;
	packetdata.u.Cpm.addr = addr;
	packetdata.u.Cpm.buffer = buffer;
	packetdata.u.Cpm.size = nSize;
	packetdata.u.Cpm.ret_size = lpNumberOfBytesWritten;
	return NtCall(&packetdata);
}

NTSTATUS Driver::AllocateVirtualMemory(HANDLE pid, ptr* addr, u32 ZeroBits, u64* RegionSize, u32 AllocationType, u32 Protect)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__AllocMemory;
	packetdata.u.Alm.pid = pid;
	packetdata.u.Alm.addr = addr;
	packetdata.u.Alm.ZeroBits = ZeroBits;
	packetdata.u.Alm.RegionSize = RegionSize;
	packetdata.u.Alm.Type = AllocationType;
	packetdata.u.Alm.Protect = Protect;
	return NtCall(&packetdata);
}

NTSTATUS Driver::FreeVirtualMemory(HANDLE pid, ptr* addr, u64* RegionSize, u32 FreeType)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__FreeMemory;
	packetdata.u.Alm.pid = pid;
	packetdata.u.Alm.addr = addr;
	packetdata.u.Alm.RegionSize = RegionSize;
	packetdata.u.Alm.Type = FreeType;
	return NtCall(&packetdata);
}

NTSTATUS Driver::QueryVirtualMemory(HANDLE pid, ptr addr, u32 InfoClass, ptr* info, u64 size, u64* returnlenghut)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__QueryMemory;
	packetdata.u.Qum.pid = pid;
	packetdata.u.Qum.addr = addr;
	packetdata.u.Qum.InfoClass = InfoClass;
	packetdata.u.Qum.info = info;
	packetdata.u.Qum.size = size;
	packetdata.u.Qum.returnlenghut = returnlenghut;
	return NtCall(&packetdata);

}

NTSTATUS Driver::ProtectVirtualMemory(HANDLE pid, ptr* addr, u32* ProtectSize, u32 NewProtect, u32* OldProtect)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__ProtectMemory;
	packetdata.u.Prm.pid = pid;
	packetdata.u.Prm.addr = addr;
	packetdata.u.Prm.ProtectSize = ProtectSize;
	packetdata.u.Prm.NewProtect = NewProtect;
	packetdata.u.Prm.OldProtect = OldProtect;
	return NtCall(&packetdata);
}

NTSTATUS Driver::ResumeProcess(HANDLE pid)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__ResumeProcess;
	packetdata.u.Syh.pid = pid;
	return NtCall(&packetdata);
}

NTSTATUS Driver::SuspendProcess(HANDLE pid)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__SuspendProcess;
	packetdata.u.Syh.pid = pid;
	return NtCall(&packetdata);
}

NTSTATUS Driver::SetContextThread(HANDLE ThreadId, PCONTEXT Context)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__SetContext;
	packetdata.u.Thc.tid = ThreadId;
	packetdata.u.Thc.context = Context;
	return NtCall(&packetdata);
}

NTSTATUS Driver::GetContextThread(HANDLE ThreadId, PCONTEXT Context)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__GetContext;
	packetdata.u.Thc.tid = ThreadId;
	packetdata.u.Thc.context = Context;
	return NtCall(&packetdata);
}

NTSTATUS Driver::SuspendThread(HANDLE ThreadId, u32* PreviousSuspendCount)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__SuspendThread;
	packetdata.u.Syh.t.tid = ThreadId;
	packetdata.u.Syh.t.count = PreviousSuspendCount;
	return NtCall(&packetdata);
}

NTSTATUS Driver::ResumeThread(HANDLE ThreadId, u32* PreviousSuspendCount)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__ResumeThread;
	packetdata.u.Syh.t.tid = ThreadId;
	packetdata.u.Syh.t.count = PreviousSuspendCount;
	return NtCall(&packetdata);
}

NTSTATUS Driver::SetInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__SetProcess;
	packetdata.u.Qpi.processid = processid;
	packetdata.u.Qpi.ProcessInformationClass = ProcessInformationClass;
	packetdata.u.Qpi.ProcessInformation = ProcessInformation;
	packetdata.u.Qpi.ProcessInformationLength = ProcessInformationLength;

	return NtCall(&packetdata);
}

NTSTATUS Driver::QueryInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__QueryProcess;
	packetdata.u.Qpi.processid = processid;
	packetdata.u.Qpi.ProcessInformationClass = ProcessInformationClass;
	packetdata.u.Qpi.ProcessInformation = ProcessInformation;
	packetdata.u.Qpi.ProcessInformationLength = ProcessInformationLength;
	packetdata.u.Qpi.ReturnLength = ReturnLength;
	return NtCall(&packetdata);
}

NTSTATUS Driver::OpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__OpenProcess;
	packetdata.u.Oph.ProcessHandle = ProcessHandle;
	packetdata.u.Oph.DesiredAccess = DesiredAccess;
	packetdata.u.Oph.ObjectAttributes = ObjectAttributes;
	packetdata.u.Oph.ClientId = ClientId;
	return NtCall(&packetdata);
}

NTSTATUS Driver::OpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__OpenThread;
	packetdata.u.Oph.ProcessHandle = ThreadHandle;
	packetdata.u.Oph.DesiredAccess = DesiredAccess;
	packetdata.u.Oph.ObjectAttributes = ObjectAttributes;
	packetdata.u.Oph.ClientId = ClientId;
	return NtCall(&packetdata);
}

NTSTATUS Driver::QuerySystemInformationEx(u32 SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__QuerySystem;
	packetdata.u.Qsi.SystemInformationClass = SystemInformationClass;
	packetdata.u.Qsi.InputBuffer = InputBuffer;
	packetdata.u.Qsi.InputBufferLength = InputBufferLength;
	packetdata.u.Qsi.SystemInformation = SystemInformation;
	packetdata.u.Qsi.SystemInformationLength = SystemInformationLength;
	packetdata.u.Qsi.ReturnLength = ReturnLength;
	return NtCall(&packetdata);
}

NTSTATUS Driver::QuerySystemInformation(u32 SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__QuerySystem;
	packetdata.u.Qsi.SystemInformationClass = SystemInformationClass;
	packetdata.u.Qsi.SystemInformation = SystemInformation;
	packetdata.u.Qsi.SystemInformationLength = SystemInformationLength;
	packetdata.u.Qsi.ReturnLength = ReturnLength;
	return NtCall(&packetdata);
}

NTSTATUS Driver::CreateThread(HANDLE handle,PVOID start,PVOID parameter)
{
	PacketData packetdata = PacketData();
	packetdata.byte = PACKETENUM::__CreateThread;
	packetdata.u.Cti.handle = handle;
	packetdata.u.Cti.start = start;
	packetdata.u.Cti.parameter = parameter;
	return NtCall(&packetdata);
}

NTSTATUS Driver::ApcExecutionCode(HANDLE handle, PVOID address, PVOID parameter)
{
	PacketData packetdata = PacketData();
	CONTEXT context = CONTEXT();
	packetdata.byte = PACKETENUM::__ApcRipExecutionCode;
	packetdata.u.ARE.ProcessHandle = handle;
	packetdata.u.ARE.Address = address;
	packetdata.u.ARE.Parameter = parameter;
	packetdata.u.ARE.Context = &context;
	return NtCall(&packetdata);
}