#pragma once

typedef long long s64;
typedef unsigned long long u64;

typedef long s32;
typedef unsigned long u32;

typedef short s16;
typedef unsigned short u16;

typedef char s8;
typedef unsigned char u8;

typedef void* ptr;
typedef void* p;
typedef u8* bptr;
typedef u16* wptr;
typedef u32* dptr;
typedef u64* qptr;


#define rptr(x)			*(void**)(x)

#define rbyte(x)		*(unsigned char*)(x)
#define rword(x)		*(unsigned short*)(x)
#define rdword(x)		*(unsigned long*)(x)
#define rqword(x)		*(unsigned long long*)(x)

#define rchar(x)		*(char*)(x)
#define rshort(x)		*(short*)(x)
#define rlong(x)		*(long*)(x)
#define rllong(x)		*(long long*)(x)

#define wbyte(x,n)		*(unsigned char*)(x) = (unsigned char)(n)
#define wword(x,n)		*(unsigned short*)(x) = (unsigned short)(n)
#define wdword(x,n)		*(unsigned long*)(x) = (unsigned long)(n)
#define wqword(x,n)		*(unsigned long long*)(x) = (unsigned long long)(n)

#define wchar(x,n)		*(char*)(x) = (char)(n)
#define wshort(x,n)		*(short*)(x) = (short)(n)
#define wlong(x,n)		*(long*)(x) = (long)(n)
#define wllong(x,n)		*(long long*)(x) = (long long)(n)



#define toU64(x)			(u64)(x)
#define toU32(x)			(u32)(x)
#define toU16(x)			(u16)(x)
#define toU8(x)				(u8)(x)

#define toS64(x)			(s64)(x)
#define toS32(x)			(s32)(x)
#define toS16(x)			(s16)(x)
#define toS8(x)				(s8)(x)



#define DriverName 'YLCE'


typedef struct
{
	u64 NtOpenProcess;
	u64 NtReadProcessMemory;
	u64 NtWriteProcessMemory;
	u64 PsSuspendProcess;
	u64 PsResumeProcess;
	u64 NtQuerySystemInformation;
	u64 NtQuerySystemInformationEx;
	u64 NtQueryInformationProcess;
	u64 NtSetInformationProcess;
	u64 NtFlushInstructionCache;
	u64 NtQueryVirtualMemory;

	u64 NtFlushVirtualMemory;
	u64 NtLockVirtualMemory;
	u64 NtUnlockVirtualMemory;
	u64 NtProtectVirtualMemory;

	u64 NtOpenThread;
	u64 NtQueryInformationThread;
	u64 NtSetInformationThread;
	u64 PsGetContextThread;
	u64 PsSetContextThread;
	u64 PsResumeThread;
	u64 PsSuspendThread;

	u64 NtWaitForSingleObject;

	u64 PsGetNextProcessThread;
	u64 KeServiceDescriptorTable;

	u64 NtCreateThreadEx;
}NT_FUNCTION, * PNT_FUNCTION;

typedef struct
{
	u32 _KTHREAD_PreviousMode;
}NT_STRUCT_OFFSET, * PNT_STRUCT_OFFSET;


typedef struct
{
	NT_FUNCTION				nt;
	NT_STRUCT_OFFSET		ntOffset;
} SYMBOL_FUNCTION_ADDR, * PSYMBOL_FUNCTION_ADDR;

typedef struct
{
	HANDLE pid;
	ptr addr;
	ptr buffer;
	u64 size;
	u64* ret_size;
}COPY_MEMORY, * PCOPY_MEMORY;

typedef struct
{
	HANDLE pid;
	ptr* addr;
	u32 ZeroBits;
	u64* RegionSize;
	u32 Type;
	u32 Protect;
}ALLOC_MEMORY, * PALLOC_MEMORY;

typedef struct
{
	HANDLE pid;
	ptr addr;
	u32 InfoClass;
	ptr* info;
	u64 size;
	u64* returnlenghut;
}QUERY_MEMORY, * PQUERY_MEMORY;

typedef struct
{
	HANDLE pid;
	ptr* addr;
	u32* ProtectSize;
	u32 NewProtect;
	u32* OldProtect;
}PROTECT_MEMORY,* PPROTECT_MEMORY;

typedef struct
{
	HANDLE tid;
	PCONTEXT context;
}THREAD_CONTEXT;

typedef struct
{
	HANDLE handle;
	PVOID start;
	PVOID parameter;
}CREATE_THREAD;

typedef struct
{
	union 
	{
		HANDLE pid;
		struct 
		{
			HANDLE tid;
			u32*  count;
		}t;
	};
}SYSPEND_HANDLE;

typedef struct
{
	HANDLE processid;
	PROCESSINFOCLASS ProcessInformationClass;
	ptr ProcessInformation;
	u32 ProcessInformationLength;
	u32* ReturnLength;
}QUERY_PROCESS_INFO;

typedef struct
{
	u32 SystemInformationClass;
	PVOID InputBuffer;
	ULONG InputBufferLength;
	PVOID SystemInformation;
	ULONG SystemInformationLength;
	PULONG ReturnLength;
}QUERY_SYSTEM_INFO, * PQUERY_SYSTEM_INFO;


typedef struct
{
	PHANDLE            ProcessHandle;
	ACCESS_MASK        DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID*         ClientId;
}OPEN_HANDLE, * POPEN_HANDLE;

typedef struct
{
	HANDLE				ProcessHandle;
	PVOID				Address;
	PVOID				Parameter;
	PCONTEXT			Context;
}APC_RIPEXECUTION_CODE, *PAPC_RIPEXECUTION_CODE;


enum class PACKETENUM
{
	__TestLoading = 0,
	__SendSymBol,
	__ReadMemory,
	__WriteMemory,
	__AllocMemory,
	__ProtectMemory,
	__FreeMemory,
	__QueryMemory,
	__CreateThread,
	__SuspendThread,
	__ResumeThread,
	__SuspendProcess,
	__ResumeProcess,
	__GetContext,
	__SetContext,
	__QueryProcess,
	__SetProcess,
	__QueryThread,
	__SetThread,
	__QuerySystem,
	__OpenProcess,
	__OpenThread,
	__ApcRipExecutionCode
};

typedef struct
{
	PACKETENUM byte;
	union
	{
		SYMBOL_FUNCTION_ADDR	Sym;
		COPY_MEMORY				Cpm;
		ALLOC_MEMORY			Alm;
		QUERY_MEMORY			Qum;
		PROTECT_MEMORY			Prm;
		SYSPEND_HANDLE			Syh;
		THREAD_CONTEXT			Thc;
		QUERY_PROCESS_INFO		Qpi;
		OPEN_HANDLE				Oph;
		QUERY_SYSTEM_INFO		Qsi;
		CREATE_THREAD			Cti;
		APC_RIPEXECUTION_CODE	ARE;
	}u;
}PacketData, * PPacketData;
