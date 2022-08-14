#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif 

#include <Windows.h>
#include <stdio.h>
#include <io.h>
#include <atlcomcli.h>
#include <Psapi.h>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <DbgHelp.h>
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib, "urlmon.lib")
#include "PDBHelp.h"

#include "utils.h"

typedef struct _IMAGE_DEBUG_DIRECTORY_RAW {
	uint8_t format[4];
	uint8_t PdbSignature[16];
	uint32_t PdbDbiAge;
	uint8_t ImageName[256];
} IMAGE_DEBUG_DIRECTORY_RAW, * PIMAGE_DEBUG_DIRECTORY_RAW;

PDBHelp::PDBHelp(std::string pdbpath) :
	m_pdbpath(pdbpath),
	hProcess(GetCurrentProcess())
{
	SymInitialize(hProcess, 0, FALSE);
	std::string str("srv*");
	str = str + pdbpath + "*http://msdl.microsoft.com/download/symbols";
	SymSetSearchPath(hProcess, str.c_str());
}

PDBHelp::~PDBHelp()
{
	for (auto& info : PDBBase)
		SymUnloadModule64(hProcess, info.second);

	SymCleanup(hProcess);
}

bool PDBHelp::FileDownloader(
	std::string& PdbName,
	std::string& url
)
{
	auto path = m_pdbpath + PdbName;
	if (_access(path.c_str(), 4))
		return SUCCEEDED(URLDownloadToFileA(NULL, url.c_str(), path.c_str(), 0, NULL)) ? TRUE : FALSE;
	else
		return TRUE;
}

void PDBHelp::PEHeaderReader(
	std::string* PEFileName,
	std::string* url)
{
	FILE* File = NULL;
#ifndef _WIN64
	PVOID OldValue = NULL;
	if (!Wow64DisableWow64FsRedirection(&OldValue))
		return;
	File = fopen(PEFileName->c_str(), "rb");
	Wow64RevertWow64FsRedirection(OldValue);
#else
	File = fopen(PEFileName->c_str(), "rb");
#endif // WIN32
	if (!File)
		return;
	IMAGE_DOS_HEADER DosHeader;
	fread(&DosHeader, sizeof(IMAGE_DOS_HEADER), 1, File);
	fseek(File, DosHeader.e_lfanew, SEEK_SET);

	// Add 4 bytes to the offset
	uint32_t NtHeadersSignature;
	fread(&NtHeadersSignature, 4, 1, File);

	IMAGE_FILE_HEADER FileHeader;
	fread(&FileHeader, sizeof(IMAGE_FILE_HEADER), 1, File);

	uint32_t is32BitHeader = FileHeader.Machine == IMAGE_FILE_MACHINE_I386;

	IMAGE_OPTIONAL_HEADER32 OptionalHeader32 = { 0 };
	IMAGE_OPTIONAL_HEADER64 OptionalHeader64 = { 0 };

	if (is32BitHeader)
		fread(&OptionalHeader32, sizeof(IMAGE_OPTIONAL_HEADER32), 1, File);
	else
		fread(&OptionalHeader64, sizeof(IMAGE_OPTIONAL_HEADER64), 1, File);

	uint32_t offDebug = 0;
	uint32_t cbFromHeader = 0;

	uint32_t cbDebug = is32BitHeader ?
		OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size : OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

	for (int HeaderNo = 0; HeaderNo < FileHeader.NumberOfSections; ++HeaderNo) {
		IMAGE_SECTION_HEADER SectionHeader;
		fread(&SectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, File);

		if ((SectionHeader.PointerToRawData != 0) && (SectionHeader.SizeOfRawData != 0) &&
			(cbFromHeader < (SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData))) {
			cbFromHeader = SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData;
		}

		if (cbDebug != 0) {
			if (is32BitHeader) {
				if (SectionHeader.VirtualAddress <= OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress &&
					((SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData) > OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress)) {
					offDebug = OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;
				}
			}

			else {
				if (SectionHeader.VirtualAddress <= OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress &&
					((SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData) > OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress)) {
					offDebug = OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;
				}
			}
		}
	}

	fseek(File, offDebug, SEEK_SET);

	uint8_t loopexit = FALSE;

	IMAGE_DEBUG_DIRECTORY_RAW DebugRaw;
	while (cbDebug >= sizeof(IMAGE_DEBUG_DIRECTORY)) {

		if (loopexit == FALSE) {

			IMAGE_DEBUG_DIRECTORY DebugDirectory;

			fread(&DebugDirectory, sizeof(IMAGE_DEBUG_DIRECTORY), 1, File);

			uint32_t seekPosition = ftell(File);

			if (DebugDirectory.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
				fseek(File, DebugDirectory.PointerToRawData, SEEK_SET);
				fread(&DebugRaw, sizeof(IMAGE_DEBUG_DIRECTORY_RAW), 1, File);
				loopexit = TRUE;

				// Downloading logic for .NET native images
				if (strstr((char*)DebugRaw.ImageName, ".ni.") != 0) {
					fseek(File, seekPosition, SEEK_SET);
					loopexit = FALSE;
				}
			}

			if ((DebugDirectory.PointerToRawData != 0) && (DebugDirectory.SizeOfData != 0) &&
				(cbFromHeader < (DebugDirectory.PointerToRawData + DebugDirectory.SizeOfData))) {
				cbFromHeader = DebugDirectory.PointerToRawData + DebugDirectory.SizeOfData;
			}
		}

		cbDebug -= sizeof(IMAGE_DEBUG_DIRECTORY);
	}

	fclose(File);

	if (loopexit) {

		const char MsServer[] = "http://msdl.microsoft.com/download/symbols";
		char TempUrl[MAX_PATH] = { 0 };
		sprintf(
			TempUrl, "%s/%s/%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%d/%s",
			MsServer,
			DebugRaw.ImageName,
			DebugRaw.PdbSignature[3], DebugRaw.PdbSignature[2], DebugRaw.PdbSignature[1], DebugRaw.PdbSignature[0],
			DebugRaw.PdbSignature[5], DebugRaw.PdbSignature[4],
			DebugRaw.PdbSignature[7], DebugRaw.PdbSignature[6],
			DebugRaw.PdbSignature[8], DebugRaw.PdbSignature[9],
			DebugRaw.PdbSignature[10], DebugRaw.PdbSignature[11], DebugRaw.PdbSignature[12],
			DebugRaw.PdbSignature[13], DebugRaw.PdbSignature[14], DebugRaw.PdbSignature[15],
			DebugRaw.PdbDbiAge,
			DebugRaw.ImageName
		);
		*url = TempUrl;
	}
	else {
		printf("PEHeaderReader Error: Invalid PE\n");
	}
}


bool PDBHelp::Load(std::string pdbname, uint64_t Base)
{
	if (Base == NULL)
		Base = (PDBBase.size() + 1) * 0x100000000;
	std::string path = m_pdbpath + pdbname;
	auto ModuleBase = SymLoadModuleEx(hProcess, NULL, path.c_str(), NULL, Base, NULL, NULL, NULL);
	if (ModuleBase)
	{
		PDBBase[pdbname] = ModuleBase;
		return true;
	}
	else
		return false;
}


uint64_t PDBHelp::GetSymFuncAddr(std::string funcname, bool& hr)
{
	char szSymbolName[MAX_SYM_NAME];
	ULONG64 buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(TCHAR) +
		sizeof(ULONG64) - 1) /
		sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	strcpy_s(szSymbolName, sizeof(szSymbolName), funcname.c_str());
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	return SymFromName(hProcess, szSymbolName, pSymbol) ? pSymbol->Address : NULL;
}

uint64_t PDBHelp::GetSymFuncAddr(std::string funcname)
{
	char szSymbolName[MAX_SYM_NAME];
	ULONG64 buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(TCHAR) +
		sizeof(ULONG64) - 1) /
		sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	strcpy_s(szSymbolName, sizeof(szSymbolName), funcname.c_str());
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	return SymFromName(hProcess, szSymbolName, pSymbol) ? pSymbol->Address : NULL;
}

uint64_t PDBHelp::GetSymFuncOffset(std::string funcname, bool& hr)
{
	char szSymbolName[MAX_SYM_NAME];
	ULONG64 buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(TCHAR) +
		sizeof(ULONG64) - 1) /
		sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	strcpy_s(szSymbolName, sizeof(szSymbolName), funcname.c_str());
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	return SymFromName(hProcess, szSymbolName, pSymbol) ? pSymbol->Address - pSymbol->ModBase : NULL;
}

uint64_t PDBHelp::GetSymFuncOffset(std::string funcname)
{
	char szSymbolName[MAX_SYM_NAME];
	ULONG64 buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(TCHAR) +
		sizeof(ULONG64) - 1) /
		sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	strcpy_s(szSymbolName, sizeof(szSymbolName), funcname.c_str());
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	return SymFromName(hProcess, szSymbolName, pSymbol) ? pSymbol->Address - pSymbol->ModBase : NULL;
}


BOOL
TestEnumSym(
	_In_ PSYMBOL_INFO pSymInfo,
	_In_ ULONG SymbolSize,
	_In_opt_ PVOID UserContext
);

void PDBHelp::EnumSymType(std::string SymNmae, std::string TypeName)
{
	if (PDBBase.find(SymNmae) == PDBBase.end())
	{
		return;
	}

	uint64_t buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(wchar_t) +
		sizeof(uint64_t) - 1) /
		sizeof(uint64_t)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	if (!SymGetTypeFromName(hProcess, PDBBase[SymNmae], TypeName.c_str(), pSymbol))
	{
		return;
	}
	uint32_t ElementCount = { 0 };
	if (!SymGetTypeInfo(hProcess, PDBBase[SymNmae], pSymbol->TypeIndex, TI_GET_CHILDRENCOUNT, &ElementCount))
	{
		return;
	}
	TI_FINDCHILDREN_PARAMS* pCP = (TI_FINDCHILDREN_PARAMS*)new char[(sizeof(ULONG) * (2 + ElementCount))];
	memset(pCP, 0, sizeof(ULONG) * (2 + ElementCount));

	pCP->Count = ElementCount;
	if (!SymGetTypeInfo(hProcess, PDBBase[SymNmae], pSymbol->TypeIndex, TI_FINDCHILDREN, pCP))
	{
		delete pCP;
		return;
	}
	WCHAR* pNameW = NULL;
	DWORD Offset = NULL;

	for (uint32_t i = 0; i < ElementCount; ++i)
	{
		if (SymGetTypeInfo(hProcess, PDBBase[SymNmae],
			pCP->ChildId[i], TI_GET_SYMNAME, &pNameW))
		{
			SymGetTypeInfo(hProcess, PDBBase[SymNmae], pCP->ChildId[i], TI_GET_OFFSET, &Offset);
			printf("Offset:%08X Name:%ws\n", Offset, pNameW);
		}
		else
			break;
	}
	delete pCP;
	return;
}


uint32_t PDBHelp::GetSymTypeOffset(std::string SymNmae, std::string TypeName, std::string ChildName, bool& hr)
{
	if (PDBBase.find(SymNmae) == PDBBase.end())
	{
		hr = false;
		return 0;
	}

	uint64_t buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(wchar_t) +
		sizeof(uint64_t) - 1) /
		sizeof(uint64_t)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	if (!SymGetTypeFromName(hProcess, PDBBase[SymNmae], TypeName.c_str(), pSymbol))
	{
		hr = false;
		return 0;
	}
	uint32_t ElementCount = { 0 };
	if (!SymGetTypeInfo(hProcess, PDBBase[SymNmae], pSymbol->TypeIndex, TI_GET_CHILDRENCOUNT, &ElementCount))
	{
		hr = false;
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* pCP = (TI_FINDCHILDREN_PARAMS*)new char[(sizeof(ULONG) * (2 + ElementCount))];
	memset(pCP, 0, sizeof(ULONG) * (2 + ElementCount));

	pCP->Count = ElementCount;
	if (!SymGetTypeInfo(hProcess, PDBBase[SymNmae], pSymbol->TypeIndex, TI_FINDCHILDREN, pCP))
	{
		hr = false;
		delete pCP;
		return 0;
	}
	WCHAR* pNameW = NULL;
	DWORD Offset = NULL;

	std::wstring str = CA2W(ChildName.c_str()).m_psz;

	for (uint32_t i = 0; i < ElementCount; ++i)
	{
		if (SymGetTypeInfo(hProcess, PDBBase[SymNmae],
			pCP->ChildId[i], TI_GET_SYMNAME, &pNameW))
		{
			if (str == pNameW)
			{
				SymGetTypeInfo(hProcess, PDBBase[SymNmae], pCP->ChildId[i], TI_GET_OFFSET, &Offset);
				break;
			}
		}
		else
		{
			hr = false;
			Offset = 0;
			break;
		}
	}
	delete pCP;
	return Offset;
}

uint32_t PDBHelp::GetSymTypeOffset(std::string SymNmae, std::string TypeName, std::string ChildName)
{
	bool hr = false;
	return this->GetSymTypeOffset(SymNmae, TypeName, ChildName, hr);
}

uint64_t PDBHelp::GetKernelModuleBase(std::string modulename)
{
	PVOID drivers[1024];
	DWORD cbNeeded;
	int cDrivers, i;
	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		CHAR szDriver[MAX_PATH];
		cDrivers = cbNeeded / sizeof(drivers[0]);
		for (i = 0; i < cDrivers; i++)
		{
			if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				std::string DriverName(szDriver);
				if (modulename == DriverName)
					return (uint64_t)drivers[i];
			}
		}
	}
	return NULL;
}

