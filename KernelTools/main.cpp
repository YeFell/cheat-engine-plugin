#include "global.h"
#include "../include/CppSupport.h"



PDRIVER_OBJECT g_DriverObject = NULL;
KHack* kh;

NTSTATUS MyBiosCallBack(PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo)
{

	NTSTATUS status = STATUS_SUCCESS;
	if (KeGetCurrentIrql() >= APC_LEVEL)
		return status;
	if (ExGetPreviousMode() != UserMode)
		return status;
	PPacketData PacketData = (*(PPacketData*)(&SystemFirmwareTableInfo->Action));
	__try
	{
		switch (PacketData->byte)
		{
		case PACKETENUM::__TestLoading:
			status = STATUS_SUCCESS;
			break;
		case PACKETENUM::__SendSymBol:
		{
			kh->symbol = PacketData->u.Sym;
			auto Nt = (uint64_t*)&kh->symbol.nt;
			for (size_t i = 0; i < sizeof(NT_FUNCTION) / sizeof(u64); i++)
			{
				if (!Nt[i])
				{
					Dbprint("Symbol Error!");
					status = STATUS_UNSUCCESSFUL;
				}
				Dbprint("point:%llX", Nt[i]);
			}

			break;
		}
		case PACKETENUM::__ReadMemory:
		{
			status = kh->ntfun->ReadProcessMemory(
				PacketData->u.Cpm.pid,
				PacketData->u.Cpm.addr,
				PacketData->u.Cpm.buffer,
				PacketData->u.Cpm.size,
				PacketData->u.Cpm.ret_size);
			break;
		}
		case PACKETENUM::__WriteMemory:
		{
			//Dbprint("w hp:%X addr:%llX buffer:%llX size:%X retSize:%llX",
			//	PacketData->u.Cpm.pid,
			//	PacketData->u.Cpm.addr,
			//	PacketData->u.Cpm.buffer,
			//	PacketData->u.Cpm.size,
			//	PacketData->u.Cpm.ret_size);

			status = kh->ntfun->WriteProcessMemory(
				PacketData->u.Cpm.pid,
				PacketData->u.Cpm.addr,
				PacketData->u.Cpm.buffer,
				PacketData->u.Cpm.size,
				PacketData->u.Cpm.ret_size);
			break;
		}
		case PACKETENUM::__AllocMemory:
		{
			status = kh->ntfun->AllocateVirtualMemory(
				PacketData->u.Alm.pid,
				PacketData->u.Alm.addr,
				PacketData->u.Alm.ZeroBits,
				PacketData->u.Alm.RegionSize,
				PacketData->u.Alm.Type,
				PacketData->u.Alm.Protect
			);
			break;
		}
		case PACKETENUM::__ProtectMemory:
		{
			status = kh->ntfun->ProtectVirtualMemory(
				PacketData->u.Prm.pid,
				PacketData->u.Prm.addr,
				PacketData->u.Prm.ProtectSize,
				PacketData->u.Prm.NewProtect,
				PacketData->u.Prm.OldProtect
			);
			break;
		}
		case PACKETENUM::__FreeMemory:
		{
			status = kh->ntfun->FreeVirtualMemory(
				PacketData->u.Alm.pid,
				PacketData->u.Alm.addr,
				PacketData->u.Alm.RegionSize,
				PacketData->u.Alm.Type
			);
			break;
		}
		case PACKETENUM::__QueryMemory:
		{
			//Dbprint("q hp:%X addr:%llX class:%d buffer:%llX size:%X retSize:%llX",
			//	PacketData->u.Qum.pid,
			//	PacketData->u.Qum.addr,
			//	PacketData->u.Qum.InfoClass,
			//	PacketData->u.Qum.info,
			//	PacketData->u.Qum.size,
			//	PacketData->u.Qum.returnlenghut
			//	);	

			status = kh->ntfun->QueryVirtualMemory(
				PacketData->u.Qum.pid,
				PacketData->u.Qum.addr,
				(MEMORY_INFORMATION_CLASS)PacketData->u.Qum.InfoClass,
				PacketData->u.Qum.info,
				PacketData->u.Qum.size,
				PacketData->u.Qum.returnlenghut
			);
			break;
		}
		case PACKETENUM::__CreateThread:
			status = kh->ntfun->CreateThread(PacketData->u.Cti.handle, PacketData->u.Cti.start, PacketData->u.Cti.parameter);
			break;
		case PACKETENUM::__SuspendThread:
		{
			status = kh->ntfun->SuspendThread(PacketData->u.Syh.t.tid, PacketData->u.Syh.t.count);
			break;
		}
		case PACKETENUM::__ResumeThread:
		{
			status = kh->ntfun->ResumeThread(PacketData->u.Syh.t.tid, PacketData->u.Syh.t.count);
			break;
		}
		case PACKETENUM::__SuspendProcess:
		{
			status = kh->ntfun->SuspendProcess(PacketData->u.Syh.pid);
			break;
		}
		case PACKETENUM::__ResumeProcess:
		{
			status = kh->ntfun->ResumeProcess(PacketData->u.Syh.pid);
			break;
		}
		case PACKETENUM::__GetContext:
		{
			status = kh->ntfun->GetContextThread(PacketData->u.Thc.tid, PacketData->u.Thc.context);
			break;
		}
		case PACKETENUM::__SetContext:
		{
			status = kh->ntfun->SetContextThread(PacketData->u.Thc.tid, PacketData->u.Thc.context);
			break;
		}
		case PACKETENUM::__QueryProcess:
		{
			status = kh->ntfun->QueryInformationProcess(
				PacketData->u.Qpi.processid,
				PacketData->u.Qpi.ProcessInformationClass,
				PacketData->u.Qpi.ProcessInformation,
				PacketData->u.Qpi.ProcessInformationLength,
				PacketData->u.Qpi.ReturnLength);
			break;
		}
		case PACKETENUM::__SetProcess:
		{
			status = kh->ntfun->SetInformationProcess(
				PacketData->u.Qpi.processid,
				PacketData->u.Qpi.ProcessInformationClass,
				PacketData->u.Qpi.ProcessInformation,
				PacketData->u.Qpi.ProcessInformationLength);
			break;
		}
		case PACKETENUM::__QueryThread:
			break;
		case PACKETENUM::__SetThread:
			break;
		case PACKETENUM::__QuerySystem:
		{
			status = kh->ntfun->QuerySystemInformation(
				PacketData->u.Qsi.SystemInformationClass,
				PacketData->u.Qsi.InputBuffer,
				PacketData->u.Qsi.InputBufferLength,
				PacketData->u.Qsi.ReturnLength
			);
			break;
		}
		case PACKETENUM::__OpenProcess:
		{
			status = kh->ntfun->OpenProcess(
				PacketData->u.Oph.ProcessHandle,
				PacketData->u.Oph.DesiredAccess,
				PacketData->u.Oph.ObjectAttributes,
				PacketData->u.Oph.ClientId);
			break;
		}
		case PACKETENUM::__OpenThread:
		{
			status = kh->ntfun->OpenThread(
				PacketData->u.Oph.ProcessHandle,
				PacketData->u.Oph.DesiredAccess,
				PacketData->u.Oph.ObjectAttributes,
				PacketData->u.Oph.ClientId);
			break;
		}
		case PACKETENUM::__ApcRipExecutionCode:
		{
			status = kh->ntfun->RipExecutionCode(
				PacketData->u.ARE.ProcessHandle,
				PacketData->u.ARE.Address,
				PacketData->u.ARE.Parameter,
				PacketData->u.ARE.Context
			);
			break;
		}
		default:
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	}
	__except (1)
	{
		Dbprint("exceptCode:%X type:%X", GetExceptionCode(), PacketData->byte);
		status = STATUS_UNSUCCESSFUL;
	}
	return status;
}

NTSTATUS RegisterBiosCallBack(_In_ BOOLEAN Register, _In_ PVOID FunctionAddr)
{

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING DeviceName = { NULL };
	PDRIVER_OBJECT pDriver = NULL;
	RtlInitUnicodeString(&DeviceName, L"\\Driver\\PnpManager");
	status = ObReferenceObjectByName(
		&DeviceName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&pDriver);
	if (!TRACE(status))
		return status;
	ObDereferenceObject(pDriver);
	SYSTEM_FIRMWARE_TABLE_HANDLER  TableHande;
	TableHande.ProviderSignature = DriverName;
	TableHande.Register = Register;
	TableHande.FirmwareTableHandler = (PFNFTH)FunctionAddr;
	TableHande.DriverObject = pDriver;
	return ZwSetSystemInformation(
		SystemRegisterFirmwareTableInformationHandler,
		(PVOID)&TableHande,
		sizeof(SYSTEM_FIRMWARE_TABLE_HANDLER)
	);
}


void UnloadDriver(PDRIVER_OBJECT DriverObject)
{

	UNREFERENCED_PARAMETER(DriverObject);
	Dbprint("Driver Unload");

	RegisterBiosCallBack(false, MyBiosCallBack);
	delete kh;
	__crt_deinit();
}


NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;

	DriverObject->DriverUnload = UnloadDriver;
	g_DriverObject = DriverObject;
	Dbprint("Current Context Func:%s line:%d", __FUNCTION__, __LINE__);
	Dbprint("Driver Longing...");

	__crt_init();
	kh = new KHack();
	status = RegisterBiosCallBack(true, MyBiosCallBack);
	if (!TRACE(status))
	{
		Dbprint("register call back error!");
		goto __end;
	}
	

__end:
	return status;
}