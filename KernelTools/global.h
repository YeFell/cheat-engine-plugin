#pragma once
#include "ntlib.h"
#include "../common/struct.h"
#include "../common/xorstr.h"




#include "KHack.h"

extern "C" 
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);



typedef enum {

	SystemRegisterFirmwareTableInformationHandler = 75

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;



extern "C"
{
	extern KHack* kh;
	extern PDRIVER_OBJECT g_DriverObject;
	extern POBJECT_TYPE* IoDriverObjectType;
	extern PSHORT NtBuildNumber;

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwSetSystemInformation(
			IN SYSTEM_INFORMATION_CLASS	   SystemInformationClass,
			IN PVOID					   SystemInformation,
			IN ULONG					   SystemInformationLength
		);

	NTSTATUS
		MmCopyVirtualMemory(
			IN  PEPROCESS FromProcess,
			IN  CONST VOID* FromAddress,
			IN  PEPROCESS ToProcess,
			OUT PVOID ToAddress,
			IN  SIZE_T BufferSize,
			IN  KPROCESSOR_MODE PreviousMode,
			OUT PSIZE_T NumberOfBytesCopied
		);

	NTSTATUS
		ObReferenceObjectByName(
			__in PUNICODE_STRING ObjectName,
			__in ULONG Attributes,
			__in_opt PACCESS_STATE AccessState,
			__in_opt ACCESS_MASK DesiredAccess,
			__in POBJECT_TYPE ObjectType,
			__in KPROCESSOR_MODE AccessMode,
			__inout_opt PVOID ParseContext,
			__out PVOID* Object
		);


	NTKERNELAPI
		PVOID
		NTAPI
		PsGetProcessWow64Process(
			_In_ PEPROCESS Process
		);


	NTKERNELAPI
		PPEB
		NTAPI PsGetProcessPeb(
			IN PEPROCESS Process
		);

	NTSYSAPI
		UCHAR*
		PsGetProcessImageFileName(
			__in PEPROCESS Process
		);


}