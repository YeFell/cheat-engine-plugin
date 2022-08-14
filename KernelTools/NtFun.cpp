#include "global.h"
#include "NtFun.h"

NtFun::NtFun(KHack* p)
{
	this->g_kh = p;
	this->symbol = &p->symbol;
}

NtFun::~NtFun()
{

}


KPROCESSOR_MODE set_currentmode(KPROCESSOR_MODE mode)
{
	u8 temp = 0;
	__try
	{
		u8* thread = (u8*)KeGetCurrentThread();
		thread += kh->symbol.ntOffset._KTHREAD_PreviousMode;
		temp = *thread;
		*thread = mode;
	}
	__except (1)
	{
		temp = UserMode;
	}
	return temp;
}


NTSTATUS NtFun::ReadProcessMemory(HANDLE pHandle, ptr addr, ptr buffer, u64 size, u64* lpNumberOfBytesRead)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = {};
	if (!pHandle) return STATUS_INVALID_PARAMETER_1;
	if (!addr) return STATUS_INVALID_PARAMETER_2;
	if (!buffer) return STATUS_INVALID_PARAMETER_3;
	if (!size) return STATUS_INVALID_PARAMETER_4;
	if (!lpNumberOfBytesRead) return STATUS_INVALID_PARAMETER_5;
	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		__try
		{
			ULONG64 NumSize = NULL;
			status = MmCopyVirtualMemory(process, addr, PsGetCurrentProcess(), buffer, size, KernelMode, &NumSize);
			if (TRACE(status))
				*lpNumberOfBytesRead = NumSize;
		}
		__except (1)
		{
			*lpNumberOfBytesRead = NULL;
			RtlZeroMemory(buffer, size);
			status = STATUS_UNSUCCESSFUL;
		}
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::WriteProcessMemory(HANDLE  pHandle, ptr  addr, ptr buffer, u64  nSize, u64* lpNumberOfBytesWritten)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = {};
	if (!pHandle) return STATUS_INVALID_PARAMETER_1;
	if (!addr) return STATUS_INVALID_PARAMETER_2;
	if (!buffer) return STATUS_INVALID_PARAMETER_3;
	if (!nSize) return STATUS_INVALID_PARAMETER_4;
	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		__try
		{
			ULONG64 NumSize = NULL;
			status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, process, addr, nSize, KernelMode, &NumSize);
			if (TRACE(status) && lpNumberOfBytesWritten)
				*lpNumberOfBytesWritten = NumSize;
		}
		__except (1)
		{
			if (lpNumberOfBytesWritten)
				*lpNumberOfBytesWritten = NULL;
			status = STATUS_UNSUCCESSFUL;
		}
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::AllocateVirtualMemory(HANDLE pHandle, ptr* addr, u32 ZeroBits, u64* RegionSize, u32 AllocationType, u32 Protect)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = {};
	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		auto BaseAddr = *addr;
		auto BaseSize = *RegionSize;
		KeStackAttachProcess(process, &apc);
		__try
		{
			status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddr, ZeroBits, (SIZE_T*)&BaseSize, AllocationType, Protect);
			if (BaseAddr)
				RtlZeroMemory(BaseAddr, BaseSize);
		}
		__except(1)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		KeUnstackDetachProcess(&apc);
		if (NT_SUCCESS(status))
		{
			*addr = BaseAddr;
			*RegionSize = BaseSize;
		}
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::FreeVirtualMemory(HANDLE pHandle, ptr* addr, u64* RegionSize, u32 FreeType)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = {};
	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		auto BaseAddr = *addr;
		auto BaseSize = *RegionSize;
		KeStackAttachProcess(process, &apc);
		__try
		{
			status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddr, (SIZE_T*)&BaseSize, FreeType);
		}
		__finally
		{
			KeUnstackDetachProcess(&apc);
			if (NT_SUCCESS(status))
			{
				*addr = BaseAddr;
				*RegionSize = BaseSize;
			}
		}
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::QueryVirtualMemory(HANDLE pHandle, ptr addr, MEMORY_INFORMATION_CLASS InfoClass, ptr* info, u64 size, u64* returnlenghut)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = {};

	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		u64 BaseSize = 0;
		ptr* temp = (ptr*)ExAllocatePoolWithTag(NonPagedPool, size, NULL);
		if (temp)
		{
			RtlZeroMemory(temp, size);
			KeStackAttachProcess(process, &apc);
			auto mode = set_currentmode(KernelMode);
			__try
			{
				status = reinterpret_cast<NTSTATUS(*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T)>(kh->symbol.nt.NtQueryVirtualMemory)
					(NtCurrentProcess(), addr, InfoClass, temp, size, &BaseSize);
			}
			__except (1)
			{
				status = STATUS_UNSUCCESSFUL;
			}
			set_currentmode(mode);
			KeUnstackDetachProcess(&apc);
			if (TRACE(status))
			{
				__try
				{
					RtlMoveMemory(info, temp, BaseSize);
					if (returnlenghut)
						*returnlenghut = BaseSize;
				}
				__except (1)
				{
					if (returnlenghut)
						*returnlenghut = NULL;
				}
			}
			ExFreePoolWithTag(temp, NULL);
		}
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::FlushVirtualMemory(HANDLE pid, ptr* addr, u64* size, PIO_STATUS_BLOCK IoStatus)
{
	return NTSTATUS();
}

NTSTATUS NtFun::LockVirtualMemory(HANDLE pid, ptr* addr, u32* LockSize, u32 LockType)
{
	return NTSTATUS();
}

NTSTATUS NtFun::UnlockVirtualMemory(HANDLE pid, ptr* addr, u32* LockSize, u32 LockType)
{
	return NTSTATUS();
}

NTSTATUS NtFun::ProtectVirtualMemory(HANDLE pHandle, ptr* addr, u32* ProtectSize, u32 NewProtect, u32* OldProtect)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = {};

	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		ptr g_addr = *addr;
		u32 g_size = *ProtectSize;
		u32 protect = 0;

		auto mode = set_currentmode(KernelMode);
		KeStackAttachProcess(process, &apc);
		__try
		{
			status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, ptr*, u32*, u32, u32*)>(symbol->nt.NtProtectVirtualMemory)
				(NtCurrentProcess(), &g_addr, &g_size, NewProtect, &protect);
		}
		__finally
		{
			KeUnstackDetachProcess(&apc);
			set_currentmode(mode);
			if (TRACE(status))
			{
				__try
				{
					*ProtectSize = g_size;
					*addr = g_addr;
					*OldProtect = protect;
				}
				__finally
				{

				}
			}
		}
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::ResumeProcess(HANDLE pHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		status = ResumeProcess(process);
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::ResumeProcess(PEPROCESS process)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	__try
	{
		status = reinterpret_cast<NTSTATUS(NTAPI*)(PEPROCESS)>(symbol->nt.PsResumeProcess)
			(process);
	}
	__except (1)
	{
		status = STATUS_UNSUCCESSFUL;
	}
	return status;
}

NTSTATUS NtFun::SuspendProcess(HANDLE pHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	status = ObReferenceObjectByHandle(pHandle, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		status = SuspendProcess(process);
		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::SuspendProcess(PEPROCESS process)
{
	NTSTATUS status = STATUS_SUCCESS;
	__try
	{

		status = reinterpret_cast<NTSTATUS(NTAPI*)(PEPROCESS)>(symbol->nt.PsSuspendProcess)
			(process);
	}
	__except (1)
	{
		status = STATUS_UNSUCCESSFUL;
	}
	return status;
}



NTSTATUS NtFun::QuerySystemInformationEx(
	u32 SystemInformationClass,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	__try
	{
		status = reinterpret_cast<NTSTATUS(NTAPI*)(u32, PVOID, ULONG, PVOID, ULONG, PULONG)>(symbol->nt.NtQuerySystemInformationEx)
			(SystemInformationClass,
				InputBuffer,
				InputBufferLength,
				SystemInformation,
				SystemInformationLength,
				ReturnLength);
	}
	__finally
	{

	}
	return status;
}

NTSTATUS NtFun::QuerySystemInformation(
	u32 SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	__try
	{
		status = reinterpret_cast<NTSTATUS(NTAPI*)(u32, PVOID, ULONG, PULONG)>(symbol->nt.NtQuerySystemInformation)
			(SystemInformationClass,
				SystemInformation,
				SystemInformationLength,
				ReturnLength);
	}
	__finally
	{

	}
	return status;
}


NTSTATUS NtFun::QueryInformationProcess(
	HANDLE           processid,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = { 0 };
	if (!processid) return STATUS_INVALID_PARAMETER_1;
	if (!ProcessInformationClass) return STATUS_INVALID_PARAMETER_2;
	if (!ProcessInformation) return STATUS_INVALID_PARAMETER_3;
	if (!ProcessInformationLength) return STATUS_INVALID_PARAMETER_4;
	if (!ReturnLength) return STATUS_INVALID_PARAMETER_5;
	status = ObReferenceObjectByHandle(processid, NULL, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	if (TRACE(status))
	{
		auto temp = ExAllocatePoolWithTag(NonPagedPool, ProcessInformationLength, NULL);
		if (temp)
		{
			u32 retsize = 0;
			auto mode = set_currentmode(KernelMode);
			KeStackAttachProcess(process, &apc);
			__try
			{
				status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
					symbol->nt.NtQueryInformationProcess)(
						NtCurrentProcess(),
						ProcessInformationClass,
						temp,
						ProcessInformationLength,
						&retsize);
			}
			__finally
			{
				KeUnstackDetachProcess(&apc);
				set_currentmode(mode);
				if (NT_SUCCESS(status))
				{
					__try
					{
						if (ProcessInformation && temp)
							RtlMoveMemory(ProcessInformation, temp, ProcessInformationLength);
						if (ReturnLength)
							*ReturnLength = retsize;
					}
					__except (1)
					{
						if (ReturnLength)
							*ReturnLength = NULL;
					}
				}
			}
			ExFreePoolWithTag(temp, NULL);
			ObDereferenceObject(process);
		}
	}
	return status;
}

NTSTATUS NtFun::SetInformationProcess(
	HANDLE           processid,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = nullptr;
	KAPC_STATE apc = { 0 };
	if (NtCurrentProcess() == processid)
	{
		__try
		{
			status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG)>(
				symbol->nt.NtSetInformationProcess)(
					NtCurrentProcess(),
					ProcessInformationClass,
					ProcessInformation,
					ProcessInformationLength);
		}
		__except (1)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		return status;
	}
	status = PsLookupProcessByProcessId(processid, &process);
	if (TRACE(status))
	{
		u8* temp = nullptr;
		if (ProcessInformation)
		{
			temp = new u8[ProcessInformationLength];
			if (!temp)
				return STATUS_UNSUCCESSFUL;
			RtlMoveMemory(temp, ProcessInformation, ProcessInformationLength);
		}

		KeStackAttachProcess(process, &apc);
		auto mode = set_currentmode(KernelMode);
		__try
		{
			status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG)>(
				symbol->nt.NtSetInformationProcess)(
					NtCurrentProcess(),
					ProcessInformationClass,
					temp,
					ProcessInformationLength);
		}
		__finally
		{
			set_currentmode(mode);
			KeUnstackDetachProcess(&apc);
		}
		if (temp)
			delete temp;

		ObDereferenceObject(process);
	}
	return status;
}

NTSTATUS NtFun::FlushInstructionCache(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG FlushSize)
{
	return NTSTATUS();
}

NTSTATUS NtFun::GetContextThread(
	HANDLE ThreadId,
	PCONTEXT Context)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PETHREAD thread = nullptr;

	status = ObReferenceObjectByHandle(ThreadId, NULL, *PsThreadType, KernelMode, (PVOID*)&thread, NULL);
	if (TRACE(status))
	{
		status = GetContextThread(thread, Context);
		ObDereferenceObject(thread);
	}
	return status;
}


NTSTATUS NtFun::GetContextThread(
	PETHREAD thread,
	PCONTEXT Context)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	__try
	{
		status = reinterpret_cast<NTSTATUS(NTAPI*)(PETHREAD, PCONTEXT, KPROCESSOR_MODE)>(symbol->nt.PsGetContextThread)
			(thread, Context, UserMode);
	}
	__except(1)
	{
		status = STATUS_UNSUCCESSFUL;
	}
	return status;
}

NTSTATUS NtFun::SetContextThread(
	HANDLE ThreadId,
	PCONTEXT Context)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PETHREAD thread = nullptr;

	status = ObReferenceObjectByHandle(ThreadId, NULL, *PsThreadType, KernelMode, (PVOID*)&thread, NULL);
	if (TRACE(status))
	{
		status = SetContextThread(thread, Context);
		ObDereferenceObject(thread);
	}
	return status;
}

NTSTATUS NtFun::SetContextThread(
	PETHREAD thread,
	PCONTEXT Context)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	__try
	{
		status = reinterpret_cast<NTSTATUS(NTAPI*)(PETHREAD, PCONTEXT, KPROCESSOR_MODE)>(symbol->nt.PsSetContextThread)
			(thread, Context, UserMode);
	}
	__except (1)
	{
		status = STATUS_UNSUCCESSFUL;
	}
	return status;
}




NTSTATUS NtFun::SuspendThread(
	HANDLE ThreadId,
	u32* PreviousSuspendCount)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PETHREAD thread = nullptr;

	status = ObReferenceObjectByHandle(ThreadId, NULL, *PsThreadType, KernelMode, (PVOID*)&thread, NULL);
	if (TRACE(status))
	{
		__try
		{
			status = reinterpret_cast<NTSTATUS(NTAPI*)(PETHREAD, u32*)>(symbol->nt.PsSuspendThread)
				(thread, PreviousSuspendCount);
		}
		__except(1)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		ObDereferenceObject(thread);
	}
	return status;
}

NTSTATUS NtFun::ResumeThread(
	HANDLE ThreadId,
	u32* PreviousSuspendCount)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PETHREAD thread = nullptr;

	status = ObReferenceObjectByHandle(ThreadId, NULL, *PsThreadType, KernelMode, (PVOID*)&thread, NULL);
	if (TRACE(status))
	{
		__try
		{
			status = reinterpret_cast<NTSTATUS(NTAPI*)(PETHREAD, u32*)>(symbol->nt.PsResumeThread)
				(thread, PreviousSuspendCount);
		}
		__except (1)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		ObDereferenceObject(thread);
	}
	return status;
}

NTSTATUS NtFun::QueryInformationThread(
	HANDLE ThreadId,
	THREADINFOCLASS ThreadInformationClass,
	ptr ThreadInformation,
	u32 ThreadInformationLength,
	u32* ReturnLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	PETHREAD thread = nullptr;

	if (NtCurrentThread() == ThreadId)
	{
		__try
		{
			status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, ptr, u32, u32*)>
				(symbol->nt.NtQueryInformationThread)(NtCurrentThread(),
					ThreadInformationClass,
					ThreadInformation,
					ThreadInformationLength,
					ReturnLength);
		}
		__finally
		{

		}
		return status;
	}
	status = ObReferenceObjectByHandle(ThreadId, PROCESS_ALL_ACCESS, *PsThreadType, UserMode, (PVOID*)&thread, NULL);
	if (TRACE(status))
	{
		KEVENT Event = { NULL };
		KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

		struct TEMP_STRUCT
		{
			THREADINFOCLASS ThreadInformationClass;
			u32  size;
			ptr buffer;
			u32  ReturnLength;
			u64  CallAddr;
			PKEVENT PEvent;
		}Temp_Struct;
		Temp_Struct.ThreadInformationClass = ThreadInformationClass;
		Temp_Struct.size = ThreadInformationLength;
		Temp_Struct.buffer = new u8[ThreadInformationLength];
		Temp_Struct.ReturnLength = 0;
		Temp_Struct.CallAddr = g_kh->symbol.nt.NtQueryInformationThread;
		Temp_Struct.PEvent = &Event;

		status = g_kh->kapc->QueueKernelApc(
			thread,
			[](
				PKAPC Apc,
				PKNORMAL_ROUTINE* NormalRoutine,
				PVOID* NormalContext,
				PVOID* SystemArgument1,
				PVOID* SystemArgument2
				)-> void
			{
				NTSTATUS status = STATUS_SUCCESS;
				TEMP_STRUCT* Temp_Struct = (TEMP_STRUCT*)*SystemArgument1;

				__try
				{
					status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, ptr, u32, u32*)>
						(Temp_Struct->CallAddr)(NtCurrentThread(),
							Temp_Struct->ThreadInformationClass,
							Temp_Struct->buffer,
							Temp_Struct->size,
							&Temp_Struct->ReturnLength);
				}
				__finally
				{

				}
				*(NTSTATUS*)SystemArgument2 = status;
				ExFreePoolWithTag(Apc, 'TApc');
				KeSetEvent(Temp_Struct->PEvent, KernelMode, FALSE);
			},
			&Temp_Struct,
				&status);
		if (NT_SUCCESS(status))
		{
			KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
			if (NT_SUCCESS(status))
			{
				RtlMoveMemory(ThreadInformation, Temp_Struct.buffer, Temp_Struct.size);
				*ReturnLength = Temp_Struct.ReturnLength;
			}
		}
		delete Temp_Struct.buffer;
		ObDereferenceObject(thread);
	}
	return status;
}

NTSTATUS NtFun::SetInformationThread(
	HANDLE ThreadId,
	THREADINFOCLASS ThreadInformationClass,
	ptr ThreadInformation,
	u32 ThreadInformationLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	PETHREAD thread = nullptr;

	if (NtCurrentThread() == ThreadId)
	{
		__try
		{
			status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, ptr, u32)>
				(symbol->nt.NtSetInformationThread)(NtCurrentThread(),
					ThreadInformationClass,
					ThreadInformation,
					ThreadInformationLength);
		}
		__finally
		{

		}
		return status;
	}
	status = ObReferenceObjectByHandle(ThreadId, PROCESS_ALL_ACCESS, *PsThreadType, UserMode, (PVOID*)&thread, NULL);
	if (TRACE(status))
	{
		KEVENT Event = { NULL };
		KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

		struct TEMP_STRUCT
		{
			THREADINFOCLASS ThreadInformationClass;
			u32  size;
			ptr buffer;
			u64  CallAddr;
			PKEVENT PEvent;
		}Temp_Struct;
		Temp_Struct.ThreadInformationClass = ThreadInformationClass;
		Temp_Struct.size = ThreadInformationLength;
		Temp_Struct.buffer = new u8[ThreadInformationLength];
		Temp_Struct.CallAddr = g_kh->symbol.nt.NtSetInformationThread;
		Temp_Struct.PEvent = &Event;

		RtlMoveMemory(Temp_Struct.buffer, ThreadInformation, ThreadInformationLength);

		status = g_kh->kapc->QueueKernelApc(
			thread,
			[](
				PKAPC Apc,
				PKNORMAL_ROUTINE* NormalRoutine,
				PVOID* NormalContext,
				PVOID* SystemArgument1,
				PVOID* SystemArgument2
				)-> void
			{
				NTSTATUS status = STATUS_SUCCESS;
				TEMP_STRUCT* Temp_Struct = (TEMP_STRUCT*)*SystemArgument1;

				__try {
					status = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, ptr, u32)>
						(Temp_Struct->CallAddr)(NtCurrentThread(),
							Temp_Struct->ThreadInformationClass,
							Temp_Struct->buffer,
							Temp_Struct->size);
				}
				__finally
				{

				}
				*(NTSTATUS*)SystemArgument2 = status;
				ExFreePoolWithTag(Apc, 'TApc');
				KeSetEvent(Temp_Struct->PEvent, KernelMode, FALSE);
			},
			&Temp_Struct,
				&status);
		if (NT_SUCCESS(status))
			KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

		delete Temp_Struct.buffer;
		ObDereferenceObject(thread);
	}
	return status;
}


NTSTATUS NtFun::OpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	NTSTATUS	status = STATUS_SUCCESS;
	PEPROCESS	process = NULL;
	status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &process);
	if (TRACE(status))
	{
		status = ObOpenObjectByPointer(process, NULL, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, ProcessHandle);
		TRACE(status);
		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS NtFun::OpenThread(
	PHANDLE				ThreadHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES  ObjectAttributes,
	PCLIENT_ID		    ClientId
)
{

	NTSTATUS	status = STATUS_SUCCESS;
	PETHREAD    thread = NULL;
	status = PsLookupThreadByThreadId(ClientId->UniqueThread, &thread);
	if (TRACE(status))
	{
		status = ObOpenObjectByPointer(thread, NULL, NULL, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, ThreadHandle);
		TRACE(status);
		ObDereferenceObject(thread);
	}
	return status;
}

PETHREAD NtFun::GetNextThread(IN PEPROCESS Process, IN PETHREAD thread)
{
	using _PsGetProcessNextThread = PETHREAD(NTAPI*)(
		IN PEPROCESS Process,
		IN PETHREAD thread
		);
	return	reinterpret_cast<_PsGetProcessNextThread>(
		kh->symbol.nt.PsGetNextProcessThread)(
			Process,
			thread);
}

NTSTATUS NtFun::CreateThread(HANDLE handle, PVOID StartAddress, PVOID ThreadParameter)
{
	NTSTATUS		 status = { NULL };
	PEPROCESS		 peprcs = { NULL };
	status = ObReferenceObjectByHandle(handle, NULL, *PsProcessType, KernelMode, (PVOID*)&peprcs, NULL);
	if (!TRACE(status)) return status;

	PETHREAD Thread = this->GetNextThread(peprcs, NULL);
	if (!Thread)
	{
		ObDereferenceObject(peprcs);
		return STATUS_UNSUCCESSFUL;
	}

	KEVENT Event = { NULL };
	KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
	struct _TempData
	{
		PVOID StartAddress;
		PVOID ThreadParameter;
		PKEVENT PEvent;
	}TempData;

	TempData.StartAddress = StartAddress;
	TempData.ThreadParameter = ThreadParameter;
	TempData.PEvent = &Event;
	status = g_kh->kapc->QueueKernelApc(
		Thread,
		[](
			PKAPC Apc,
			PKNORMAL_ROUTINE* NormalRoutine,
			PVOID* NormalContext,
			PVOID* SystemArgument1,
			PVOID* SystemArgument2
			)-> void
		{
			NTSTATUS status = STATUS_SUCCESS;
			_TempData* ppackdata = (_TempData*)(*SystemArgument1);

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

			auto Mode = set_currentmode(KernelMode);
			HANDLE ThreadHandle = NULL;
			status = reinterpret_cast<NtCreateThreadEx>(
				kh->symbol.nt.NtCreateThreadEx)(
					&ThreadHandle,
					THREAD_ALL_ACCESS,
					NULL,
					NtCurrentProcess(),
					ppackdata->StartAddress,
					ppackdata->ThreadParameter,
					NULL,
					NULL,
					NULL,
					NULL,
					NULL);
			set_currentmode(Mode);
			if (NT_SUCCESS(status))
				NtClose(ThreadHandle);

			*(NTSTATUS*)SystemArgument2 = status;
			ExFreePoolWithTag(Apc, 'TApc');
			KeSetEvent(ppackdata->PEvent, KernelMode, FALSE);
		},
		&TempData,
			&status);

	if (NT_SUCCESS(status))
		KeWaitForSingleObject(
			&Event,
			Executive,
			KernelMode,
			FALSE,
			NULL);
	ObDereferenceObject(peprcs);
	return status;
}


unsigned char RipExecutionShellCode[] =
{ 80,83,81,82,85,86,87,65,80,65,81,65,82,65,83,65,84,65,85,65,86,65,87,156,232,8,0,0,0,0,0,0,0,0,0,0,0,88,
72,137,32,72,131,228,240,72,131,236,48,72,185,0,0,0,0,0,0,0,0,72,184,0,0,0,0,0,0,0,0,255,208,72,131,196,48,
72,141,5,203,255,255,255,72,139,32,157,65,95,65,94,65,93,65,92,65,91,65,90,65,89,65,88,95,94,93,90,89,91,88,
80,72,184,0,0,0,0,0,0,0,0,72,135,4,36,195 };
int RipExecutionCode_ages = 0x33;
int RipExecutionCode_call = 0x3D;
int RipExecutionCode_jump = 0x70;

NTSTATUS NtFun::RipExecutionCode(HANDLE handle, PVOID Address,PVOID Parameter, PCONTEXT context)
{
	NTSTATUS		 status = { NULL };
	PEPROCESS		 peprcs = { NULL };
	status = ObReferenceObjectByHandle(handle, NULL, *PsProcessType, KernelMode, (PVOID*)&peprcs, NULL);
	if (!TRACE(status)) return status;
	if (PsGetProcessWow64Process(peprcs)) return status;
		
	ptr Base = 0;
	u64 Size = 0x1000;
	status = AllocateVirtualMemory(handle, &Base, NULL, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (TRACE(status))
	{
		Dbprint("Alloc Base:%p Size:%llX", Base, Size);
		status = RipExecutionCodeSetRip(peprcs, Address, Parameter, Base, context);
	}

__End:
	ObDereferenceObject(peprcs);
	return status;
}

bool initShellCode(PEPROCESS process,u64 Address, u64 Parameter, u64 jmpAddr,u64 shellCodeBase)
{
	PVOID ShellCode = ExAllocatePoolWithTag(NonPagedPool, sizeof(RipExecutionShellCode), NULL);
	if (ShellCode)
	{
		RtlZeroMemory(ShellCode, sizeof(RipExecutionShellCode));
		RtlMoveMemory(ShellCode, RipExecutionShellCode, sizeof(RipExecutionShellCode));

		wqword(((ULONG64)ShellCode + RipExecutionCode_ages), Parameter);
		wqword(((ULONG64)ShellCode + RipExecutionCode_call), Address);
		wqword(((ULONG64)ShellCode + RipExecutionCode_jump), jmpAddr);
		auto status = NTSTATUS();
		u64 Count = 0;
		__try
		{
			status = MmCopyVirtualMemory(PsGetCurrentProcess(), ShellCode,
				process, (ptr)shellCodeBase, sizeof(RipExecutionShellCode), KernelMode, &Count);
		}
		__except (1)
		{
			status = STATUS_UNSUCCESSFUL;
		}
		ExFreePoolWithTag(ShellCode, NULL);
		return TRACE(status) ? true : false;
	}
	return false;
}

NTSTATUS NtFun::RipExecutionCodeSetRip(PEPROCESS process, PVOID Address, PVOID Parameter, PVOID shellCodeBase,PCONTEXT context)
{
	NTSTATUS		 status = { NULL };

	PETHREAD thread = GetNextThread(process, NULL);
	if (!thread)
	{
		status = STATUS_UNSUCCESSFUL;
		goto __End;
	}
	status = SuspendProcess(process);
	if (TRACE(status))
	{
		context->ContextFlags = CONTEXT_ALL;
		status = GetContextThread(thread, context);
		if (TRACE(status))
		{
			if(initShellCode(process,(u64)Address, (u64)Parameter, context->Rip, (u64)shellCodeBase))
			{
				context->Rip = (u64)shellCodeBase;
				TRACE(SetContextThread(thread, context));
			}
		}
		status = ResumeProcess(process);
	}
__End:
	return status;
}
