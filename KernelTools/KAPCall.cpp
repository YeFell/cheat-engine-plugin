#include "global.h"
#include "KAPCall.h"

KAPCall::KAPCall()
{
}

KAPCall::~KAPCall()
{
}

NTSTATUS KAPCall::QueueKernelApc(PETHREAD pThread, PKKERNEL_ROUTINE function, PVOID SystemArgument1, PVOID SystemArgument2)
{
    PRKAPC pKapc = nullptr;

    pKapc = (PRKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'TApc');
    if (nullptr == pKapc)
    {
        Dbprint("InstallKernelModeApcToInjectDll Failed to allocate memory for the APC");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(pKapc, pThread,
        OriginalApcEnvironment,
        function,
        NULL,
        NULL,
        KernelMode, NULL);

    if (!KeInsertQueueApc(pKapc, SystemArgument1, SystemArgument2, KernelMode))
    {
        ExFreePoolWithTag(pKapc, 'TApc');
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS KAPCall::QueueKernelApc(PETHREAD pThread, PKNORMAL_ROUTINE function, PVOID SystemArgument1, PVOID SystemArgument2)
{
    PRKAPC pKapc = nullptr;

    pKapc = (PRKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'TApc');

    if (nullptr == pKapc)
    {
        Dbprint("InstallKernelModeApcToInjectDll Failed to allocate memory for the APC");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(pKapc, pThread,
        OriginalApcEnvironment,
        [](
            PRKAPC Apc,
            PKNORMAL_ROUTINE* NormalRoutine,
            PVOID* NormalContext,
            PVOID* SystemArgument1,
            PVOID* SystemArgument2
            ) -> void {
                UNREFERENCED_PARAMETER(NormalRoutine);
                UNREFERENCED_PARAMETER(NormalContext);
                UNREFERENCED_PARAMETER(SystemArgument1);
                UNREFERENCED_PARAMETER(SystemArgument2);

                if (Apc)
                    ExFreePoolWithTag(Apc, 'TApc');
        },
        NULL,
        function,
        KernelMode, NULL);

    if (!KeInsertQueueApc(pKapc, SystemArgument1, SystemArgument2, IO_NO_INCREMENT))
    {
        ExFreePoolWithTag(pKapc, 'TApc');
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}
