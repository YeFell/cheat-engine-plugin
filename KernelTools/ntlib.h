#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>

#include <ntstatus.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <ntimage.h>
#include <intrin.h>
#include <fltKernel.h>

#include <string>
#include <vector>
#include <map>
#include <stdio.h>
#include <stdint.h>

#ifdef DBG
#define Dbprint(Format, ...) DbgPrint(("DT -> " Format "\n"), __VA_ARGS__)
#else
#define Dbprint(Format, ...) DbgPrint(("DT -> " Format "\n"), __VA_ARGS__)
#endif 

#ifndef DBG
//#define TRACE(x) (((NTSTATUS)(x)) >= 0)
#define TRACE(x) \
            ((((NTSTATUS)(x)) >= 0) ? \
                TRUE : \
                (Dbprint( \
                    "%hs[%d] %hs failed < %08x >\n", \
                    __FILE__, \
                    __LINE__, \
                    __FUNCDNAME__, \
                    x),/* _DebugBreak(),*/ FALSE))
#else
#define TRACE(x) \
            ((((NTSTATUS)(x)) >= 0) ? \
                TRUE : \
                (Dbprint( \
                    "%hs[%d] %hs failed < %08x >\n", \
                    __FILE__, \
                    __LINE__, \
                    __FUNCDNAME__, \
                    x),/* _DebugBreak(),*/ FALSE))
#endif




