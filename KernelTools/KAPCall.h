#pragma once


typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}	KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(
	PRKAPC Apc
	);

extern "C" void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

extern "C"  BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

typedef void (*APCCallBack) (
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
	);

class KAPCall
{
public:
	KAPCall();
	~KAPCall();
	NTSTATUS QueueKernelApc(PETHREAD pThread, PKKERNEL_ROUTINE function, PVOID SystemArgument1, PVOID SystemArgument2);

	NTSTATUS QueueKernelApc(PETHREAD pThread, PKNORMAL_ROUTINE function, PVOID SystemArgument1, PVOID SystemArgument2);
};

