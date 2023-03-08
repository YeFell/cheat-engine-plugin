# cheat engine-plugin

## 介绍

cheat-engine-plugin 是Windows平台 [cheat engine](https://cheatengine.org/) 内存作弊工具的一款插件。
他把工具的核心API 通过Hook技术，替换成自己编写的内核驱动功能，来绕过部分限制。

## 开发环境

Visual Studio 2019 (V142)

SDK 10.0.19041.0

WDK 10.0.19041.0

CESDK 6

## 提供的功能

ZwOpenProcess

ZwReadVirtualMemory

ZwWriteVirtualMemory

ZwProtectVirtualMemory

ZwAllocateVirtualMemory

ZwFreeVirtualMemory

ZwQueryVirtualMemory

ZwSuspendProcess

ZwResumeProcess

ZwCreateThreadEx

ZwGetThreadContext

ZwSetThreadContext

ZwSuspendThread

ZwResumeThread

ZwOpenThread

## 提供帮助的库

[TsudaKageyu/minhook: The Minimalistic x86/x64 API Hooking Library for Windows (github.com)](https://github.com/TsudaKageyu/minhook)

