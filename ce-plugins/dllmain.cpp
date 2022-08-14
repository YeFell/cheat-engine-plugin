// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <tlhelp32.h>

static HMODULE hModule;
static ExportedFunctions ce_sdk;
static Driver* ph;

static bool Hook;
static PVOID OldOpenProcess;
static PVOID OldOpenThread;

static PVOID OldReadMemory;
static PVOID OldWriteMemory;
static PVOID OldVirtualProtect;
static PVOID OldVirtualAlloc;
static PVOID OldVirtualFree;
static PVOID OldVirtualQuery;

static PVOID OldQueryProcess;
static PVOID OldSetProcess;

static PVOID OldQuerySystemInfoEx;

static PVOID OldGetThreadContext;
static PVOID OldSetThreadContext;

static PVOID OldCreateThread;
static PVOID OldSuspendThread;
static PVOID OldSuspendProcess;

static PVOID OldResumeThread;
static PVOID OldResumeProcess;


NTSTATUS NTAPI MyNtOpenProcess(
	PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId)
{
	if (ClientId->UniqueProcess == (HANDLE)GetCurrentProcessId())
	{
		*ProcessHandle = (HANDLE)-1;
		return NULL;
	}
	auto status = ph->OpenProcess(ProcessHandle,
		DesiredAccess, ObjectAttributes, ClientId);


	return status;

}

NTSTATUS NTAPI MyNtOpenThread(
	PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId)
{
	if (ClientId->UniqueThread == (HANDLE)GetCurrentThreadId())
	{
		*ThreadHandle = (HANDLE)-2;
		return NULL;
	}
	return ph->OpenThread(ThreadHandle,
		DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI MyReadProcessMemory(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
)
{
	if ((HANDLE)-1 == hProcess)
	{
		return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*)>(OldReadMemory)
			(hProcess,
				lpBaseAddress,
				lpBuffer,
				nSize,
				lpNumberOfBytesRead);
	}
	return ph->ReadProcessMemory(
		hProcess,
		(const ptr)lpBaseAddress,
		lpBuffer,
		nSize,
		lpNumberOfBytesRead);
}

NTSTATUS NTAPI MyWriteProcessMemory(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
)
{
	if ((HANDLE)-1 == hProcess)
	{
		return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*)>(OldWriteMemory)
			(hProcess,
				lpBaseAddress,
				lpBuffer,
				nSize,
				lpNumberOfBytesWritten);
	}
	return ph->WriteProcessMemory(
		hProcess,
		lpBaseAddress,
		(const ptr)lpBuffer,
		nSize,
		lpNumberOfBytesWritten);
}


NTSTATUS NTAPI MyProtectVirtualMemory(
	IN  HANDLE hProcess,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG RegionSize,
	IN  ULONG NewProtect,
	OUT PULONG OldProtect
)
{
	if ((HANDLE)-1 == hProcess)
	{
		return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID*, PULONG, ULONG, PULONG)>(OldVirtualProtect)
			(hProcess,
				BaseAddress,
				RegionSize,
				NewProtect,
				OldProtect);
	}
	return ph->ProtectVirtualMemory(
		hProcess,
		BaseAddress,
		RegionSize,
		NewProtect,
		OldProtect);
}


NTSTATUS NTAPI MyAllocateVirtualMemory(
	HANDLE    hProcess,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect)
{
	if ((HANDLE)-1 == hProcess)
	{
		return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(OldVirtualAlloc)
			(hProcess,
				BaseAddress,
				ZeroBits,
				RegionSize,
				AllocationType,
				Protect);
	}
	return  ph->AllocateVirtualMemory(
		hProcess,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect);
}

NTSTATUS NTAPI MyFreeVirtualMemory(
	HANDLE  hProcess,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG   FreeType
)
{
	if ((HANDLE)-1 == hProcess)
	{
		return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID*,PSIZE_T,ULONG)>(OldVirtualFree)
			(hProcess,
				BaseAddress,
				RegionSize,
				FreeType);
	}
	return (ph->FreeVirtualMemory(
		hProcess,
		BaseAddress,
		RegionSize,
		FreeType));
}

NTSTATUS NTAPI MyQueryVirtualMemory(
	HANDLE                   hProcess,
	PVOID                    BaseAddress,
	ULONG					 MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
)
{
	if ((HANDLE)-1 == hProcess)
	{
		return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T)>(OldVirtualQuery)
			(hProcess,
				BaseAddress,
				MemoryInformationClass,
				MemoryInformation,
				MemoryInformationLength,
				ReturnLength);
	}
	return  ph->QueryVirtualMemory(
		hProcess,
		BaseAddress,
		MemoryInformationClass,
		(ptr*)MemoryInformation,
		MemoryInformationLength,
		ReturnLength);
}



NTSTATUS NTAPI MyGetThreadContext(
	HANDLE    hThread,
	LPCONTEXT lpContext
)
{
	return (ph->GetContextThread(
		hThread,
		lpContext) >= NULL);
}

NTSTATUS NTAPI MySetThreadContext(
	HANDLE    hThread,
	LPCONTEXT lpContext
)
{
	return (ph->SetContextThread(
		hThread,
		lpContext) >= NULL);
}



NTSTATUS __stdcall MyQueryInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	HANDLE handle = ((HANDLE)-1 == processid) ? processid : (HANDLE)*ce_sdk.OpenedProcessID;
	return ph->QueryInformationProcess(processid, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS __stdcall MySetInformationProcess(HANDLE processid, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	HANDLE handle = ((HANDLE)-1 == processid) ? processid : (HANDLE)*ce_sdk.OpenedProcessID;
	return ph->SetInformationProcess(processid, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}


NTSTATUS __stdcall MyQuerySystemInformation(
	u32 SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	return ph->QuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI MySuspendThread(HANDLE tid, ULONG* PreviousSuspendCount)
{
	return ph->SuspendThread(tid, PreviousSuspendCount);
}

NTSTATUS NTAPI MyResumeThread(HANDLE tid, ULONG* PreviousSuspendCount)
{
	return ph->ResumeThread(tid, PreviousSuspendCount);
}

NTSTATUS NTAPI MySuspendProcess(HANDLE pid)
{
	return ph->SuspendProcess(pid);
}

NTSTATUS NTAPI MyResumeProcess(HANDLE pid)
{
	return ph->ResumeProcess(pid);
}


NTSTATUS NTAPI MyCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
)
{
	if ((HANDLE)-1 == ProcessHandle)
	{
		using NtCreateThreadEx = NTSTATUS(NTAPI*) (
			OUT PHANDLE hThread,
			IN ACCESS_MASK DesiredAccess,
			IN PVOID ObjectAttributes,
			IN HANDLE ProcessHandle,
			IN PVOID lpStartAddress,
			IN PVOID lpParameter,
			IN ULONG Flags,
			IN SIZE_T StackZeroBits,
			IN SIZE_T SizeOfStackCommit,
			IN SIZE_T SizeOfStackReserve,
			OUT PVOID lpBytesBuffer
			);

		return 	reinterpret_cast<NtCreateThreadEx>(
			OldCreateThread)(
				hThread,
				DesiredAccess,
				ObjectAttributes,
				ProcessHandle,
				lpStartAddress,
				lpParameter,
				Flags,
				StackZeroBits,
				SizeOfStackCommit,
				SizeOfStackReserve,
				lpBytesBuffer);
	}
	//auto ret = ph->CreateThread(ProcessHandle, lpStartAddress, lpParameter);
	auto ret = ph->ApcExecutionCode(ProcessHandle, lpStartAddress, lpParameter);

	if (ret >= NULL)
		*hThread = (HANDLE)1;
	return ret;
}



void __stdcall mainmenuplugin()
{
	//Utils::AttachConsole();
	Hook = !Hook;
	if (Hook)
	{
		MH_CreateHookApi(L"ntdll.dll", "ZwOpenProcess", MyNtOpenProcess, &OldOpenProcess);
		MH_CreateHookApi(L"ntdll.dll", "ZwReadVirtualMemory", MyReadProcessMemory, &OldReadMemory);
		MH_CreateHookApi(L"ntdll.dll", "ZwWriteVirtualMemory", MyWriteProcessMemory, &OldWriteMemory);
		MH_CreateHookApi(L"ntdll.dll", "ZwProtectVirtualMemory", MyProtectVirtualMemory, &OldVirtualProtect);
		MH_CreateHookApi(L"ntdll.dll", "ZwAllocateVirtualMemory", MyAllocateVirtualMemory, &OldVirtualAlloc);
		////MH_CreateHookApi(L"ntdll.dll", "ZwFreeVirtualMemory", MyFreeVirtualMemory, &OldVirtualFree);
		MH_CreateHookApi(L"ntdll.dll", "ZwQueryVirtualMemory", MyQueryVirtualMemory, &OldVirtualQuery);

		MH_CreateHookApi(L"ntdll.dll", "NtSuspendProcess", MySuspendProcess, &OldSuspendProcess);
		MH_CreateHookApi(L"ntdll.dll", "NtResumeProcess", MyResumeProcess, &OldResumeProcess);


		//MH_CreateHookApi(L"ntdll.dll", "NtQueryInformationProcess", MyQueryInformationProcess, &OldQueryProcess);
		//MH_CreateHookApi(L"ntdll.dll", "NtSetInformationProcess", MySetInformationProcess, &OldSetProcess);

		//MH_CreateHookApi(L"ntdll.dll", "NtQuerySystemInformation", MyQuerySystemInformation, &OldQuerySystemInfoEx);
		MH_CreateHookApi(L"ntdll.dll", "ZwCreateThreadEx", MyCreateThreadEx, &OldCreateThread);

		MH_CreateHookApi(L"ntdll.dll", "ZwGetThreadContext", MyGetThreadContext, &OldGetThreadContext);
		MH_CreateHookApi(L"ntdll.dll", "ZwSetThreadContext", MySetThreadContext, &OldSetThreadContext);

		MH_CreateHookApi(L"ntdll.dll", "ZwSuspendThread",MySuspendThread , &OldSuspendThread);
		MH_CreateHookApi(L"ntdll.dll", "ZwResumeThread", MyResumeThread, &OldResumeThread);

		MH_CreateHookApi(L"ntdll.dll", "ZwOpenThread", MyNtOpenThread, &OldOpenThread);

		MH_EnableHook(MH_ALL_HOOKS);
		ce_sdk.ShowMessage((char*)u8"Hook替换函数为驱动操作!");
	}
	else
	{
		MH_DisableHook(MH_ALL_HOOKS);
		MH_RemoveHook(MH_ALL_HOOKS);
		ce_sdk.ShowMessage((char*)u8"还原Hook函数!");
	}
	return;
}

void __stdcall ExecutionTest()
{
	//ph->ApcExecutionCode(ce_sdk.OpenedProcessHandle, 0x00000, 00000);
}


BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion)
{
	pv->version = CESDK_VERSION;
	pv->pluginname = (char*)"Driver-Tools-plugings";
	return TRUE;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid)
{
	ce_sdk = *ef;
	ph = new Driver;
	MAINMENUPLUGIN_INIT menu;
	menu.name = (char*)u8"驱动插件";
	menu.callbackroutine = mainmenuplugin;
	menu.shortcut = NULL;


	auto MainMenuPluginID = ce_sdk.RegisterFunction(pluginid, ptMainMenu, &menu);

	//menu.name = (char*)u8"功能测试";
	//menu.callbackroutine = ExecutionTest;
	//menu.shortcut = NULL;

	//ce_sdk.RegisterFunction(pluginid, ptMainMenu, &menu);

	if (!ph->SendSymbolData())
	{
		ce_sdk.ShowMessage((char*)u8"符号初始化失败！");
		goto __End_false;
	}
	MH_Initialize();

	return TRUE;
__End_false:
	ce_sdk.UnregisterFunction(pluginid, MainMenuPluginID);
	return FALSE;
}

BOOL __stdcall CEPlugin_DisablePlugin(void)
{
	//clean up memory you might have allocated
	Utils::DetachConsole();
	MH_Uninitialize();
	delete ph;
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	::hModule = hModule;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

