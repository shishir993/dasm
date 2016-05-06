
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#include "Scan.h"

// ctime_s requires a string buffer of at least 26 chars
#define STRLEN_CTIME    32

extern DWORD g_dwInputFileType;
extern BINFILEINFO g_binFileInfo;
extern BOOL g_fExports;
extern BOOL g_fImports;
extern BOOL g_fHeaders;	// NTHeaders, FileHeader, Optional Header

// locally global variables
static WCHAR *awszDataDirNames[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = 
		{	{ L"Exports: "},
			{ L"Imports: "},
			{ L"Resource: "},
			{ L"Exception: "},
			{ L"Security: "},
			{ L"BaseReloc: "},
			{ L"Debug: "},
			{ L"Arch: "},
			{ L"GlobalPtr: "},
			{ L"TLS: "},
			{ L"LoadCfg: "},
			{ L"BoundImp: "},
			{ L"IAT: "},
			{ L"DelayImp: "},
			{ L"COMHeader: "},
			{ L"Reserved"} };


BOOL fBeginFileScan(HANDLE hFileView, BOOL *pf64bit)
{
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hFileView;
	PIMAGE_NT_HEADERS pNTHeaders = NULL;

	#ifdef _DEBUG
		wprintf_s(L"Filebase/DOSHeader: 0x%08x\n", (DWORD)pDOSHeader);
	#endif

	// verify "MZ" in the DOS header
	if( ! (pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE) )
	{
		wprintf_s(L"Valid DOS stub not found. Aborting...\n");
		return FALSE;
	}

	pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	// set pointer to NTHeaders in the global info struct
	g_binFileInfo.pNTHeaders = pNTHeaders;

	if(g_fHeaders)
	{
		wprintf_s(L"\n* NT Headers *\n");
		wprintf_s(L"Valid DOS stub found\n");

		// verify "PE00" at offset given by e_lfanew in IMAGE_DOS_HEADER
		if( ! (pNTHeaders->Signature == IMAGE_NT_SIGNATURE) )
		{
			wprintf_s(L"Valid PE signature not found. Aborting...\n");
			return FALSE;
		}

		wprintf_s(L"Valid PE signature found at FilePtr:0x%08x\n", (DWORD)pNTHeaders-(DWORD)hFileView);

        if (!fDumpFileHeader(pNTHeaders, pf64bit))
			return FALSE;

		// optional header: IMAGE_OPTIONAL_HEADER
		wprintf_s(L"\n* IMAGE_OPTIONAL_HEADER *\n");
	
		if( ! (pNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) )
		{
			wprintf_s(L"Unsupported IMAGE_OPTIONAL_HEADER magic: %d\n", pNTHeaders->OptionalHeader.Magic);
			return FALSE;
		}

		wprintf_s(L"Size of code            : 0x%x\n", pNTHeaders->OptionalHeader.SizeOfCode);
		wprintf_s(L"Size of idata           : 0x%x\n", pNTHeaders->OptionalHeader.SizeOfInitializedData);
		wprintf_s(L"Size of udata           : 0x%x\n", pNTHeaders->OptionalHeader.SizeOfUninitializedData);
		wprintf_s(L"Preferred Image Base    : 0x%x\n", pNTHeaders->OptionalHeader.ImageBase);
		wprintf_s(L"Entry Point             : 0x%x\n", pNTHeaders->OptionalHeader.AddressOfEntryPoint);
		wprintf_s(L"Base of code            : 0x%x\n", pNTHeaders->OptionalHeader.BaseOfCode);
		wprintf_s(L"Base of data            : 0x%x\n", pNTHeaders->OptionalHeader.BaseOfData);
		wprintf_s(L"Size of headers         : 0x%08x\n", pNTHeaders->OptionalHeader.SizeOfHeaders);
		wprintf_s(L"Size of image           : 0x%x\n", pNTHeaders->OptionalHeader.SizeOfImage);
		wprintf_s(L"File alignment          : 0x%08x\n", pNTHeaders->OptionalHeader.FileAlignment);
		wprintf_s(L"Section alignment       : 0x%08x\n", pNTHeaders->OptionalHeader.SectionAlignment);

		if(g_dwInputFileType == DASM_FTYPE_EXE)
		{
			wprintf_s(L"Subsystem required      : ");
			switch(pNTHeaders->OptionalHeader.Subsystem)
			{
				case IMAGE_SUBSYSTEM_NATIVE:
					wprintf_s(L"Native. No subsystem required.\n");
					break;

				case IMAGE_SUBSYSTEM_WINDOWS_CUI:
					wprintf_s(L"Windows CommandLine\n");
					break;

				case IMAGE_SUBSYSTEM_WINDOWS_GUI:
					wprintf_s(L"Windows GUI\n");
					break;

				default:
					wprintf_s(L"Unknown\n");
			}// switch(subsystem)
		}

		fDumpDataDirectory(pNTHeaders);
	}// if(g_fHeaders)

	if(g_fExports)
		fDumpExports((DWORD)pDOSHeader, pNTHeaders, 
			&(pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));

	if(g_fImports)
		Util_fDumpIMAGE_IMPORT_DESCRIPTORS(pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, 
			pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, pNTHeaders, (DWORD)hFileView);

	return TRUE;

}// fBeginFileScan()

BOOL fDumpFileHeader(IMAGE_NT_HEADERS *pNTHeader, BOOL *pf64bit)
{
	ASSERT(pNTHeader != NULL);

	char szTimestampStr[STRLEN_CTIME];
	WORD wFileCharacs;

	static WCHAR awszCharacteristics[][32] = { 
					L"RELOCS_STRIPPED",		L"EXECUTABLE_IMAGE",
					L"LINE_NUMS_STRIPPED",	L"LOCAL_SYMS_STRIPPED",
					L"AGGRESIVE_WS_TRIM",	L"LARGE_ADDRESS_AWARE",
					L"BYTES_REVERSED_LO",	L"32BIT_MACHINE",
					L"DEBUG_STRIPPED",		L"REMOVABLE_RUN_FROM_SWAP",
					L"NET_RUN_FROM_SWAP",	L"SYSTEM",
					L"DLL",					L"UP_SYSTEM_ONLY",
					L"BYTES_REVERSED_HI" };

    *pf64bit = FALSE;

	wprintf_s(L"\n* IMAGE_FILE_HEADER *\n");
	wprintf_s(L"Machine Type            : ");

	// machine type
	switch(pNTHeader->FileHeader.Machine)
	{
		case IMAGE_FILE_MACHINE_I386:
			wprintf_s(L"i386\n");
            *pf64bit = FALSE;
			break;
        
        case IMAGE_FILE_MACHINE_AMD64:
            wprintf_s(L"x64\n");
            *pf64bit = TRUE;
            break;

		default:
			wprintf_s(L"Unsupported machine format: %x\n", pNTHeader->FileHeader.Machine);
			return FALSE;
			break;

	}// switch(machineType)

	wprintf_s(L"No. of sections         : %d\n", pNTHeader->FileHeader.NumberOfSections);
	wprintf_s(L"TimeDateStamp           : 0x%x ", pNTHeader->FileHeader.TimeDateStamp);
    if (ctime_s(szTimestampStr, _countof(szTimestampStr), (time_t*)(&(pNTHeader->FileHeader.TimeDateStamp))) == 0)
    {
        // Buffer returned from ctime_s() will have \n\0 at the end if successful
        wprintf_s(L"%S", szTimestampStr);
    }
    else
    {
        wprintf_s(L"\n");
    }
	wprintf_s(L"Pointer to symtable     : 0x%x\n", pNTHeader->FileHeader.PointerToSymbolTable);
	wprintf_s(L"No. of symbols          : %d\n", pNTHeader->FileHeader.NumberOfSymbols);
	wprintf_s(L"OptionalHeader Size     : %d\n", pNTHeader->FileHeader.SizeOfOptionalHeader);
	wprintf_s(L"File Characteristics\n");

	wFileCharacs = pNTHeader->FileHeader.Characteristics;

	DWORD dw = IMAGE_FILE_RELOCS_STRIPPED;
	int index = 0;
	for(; dw <= IMAGE_FILE_BYTES_REVERSED_HI; dw <<= 1, ++index)
	{
        if (dw & wFileCharacs)
        {
            wprintf_s(L"                        : %s\n", awszCharacteristics[index]);
        }
	}

	// file characteristics
    if (wFileCharacs & IMAGE_FILE_DLL)
    {
        g_dwInputFileType = DASM_FTYPE_DLL;
    }
    else if (wFileCharacs & IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        g_dwInputFileType = DASM_FTYPE_EXE;
    }

	return TRUE;
}


BOOL fDumpDataDirectory(IMAGE_NT_HEADERS *pNTHeader)
{
	ASSERT(pNTHeader != NULL);

	wprintf_s(L"\n* IMAGE_DATA_DIRECTORY *\n");
	wprintf_s(L"%-16s  %-8s  %8s\n", L"DataDir", L"VirtAddr", L"Size");

	DWORD nRecords = (pNTHeader->OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) ?
						IMAGE_NUMBEROF_DIRECTORY_ENTRIES : pNTHeader->OptionalHeader.NumberOfRvaAndSizes;

	for(DWORD i = 0; i < nRecords; ++i)
	{
		wprintf_s(L"%-16s  0x%-08x  0x%08x\n", awszDataDirNames[i], 
			pNTHeader->OptionalHeader.DataDirectory[i].VirtualAddress,
			pNTHeader->OptionalHeader.DataDirectory[i].Size);
	}

	return TRUE;
}


BOOL fDumpSectionHeaders(IMAGE_NT_HEADERS *pNTHeaders)
{
	ASSERT(pNTHeaders != NULL);

	PIMAGE_SECTION_HEADER pFirstSecHeader = (PIMAGE_SECTION_HEADER)( (DWORD)pNTHeaders + 
											(DWORD)sizeof(pNTHeaders->Signature) + 
											(DWORD)IMAGE_SIZEOF_FILE_HEADER + 
											(DWORD)pNTHeaders->FileHeader.SizeOfOptionalHeader );

	#ifdef _DEBUG
		PIMAGE_SECTION_HEADER pFirstSecHeader_Verify = IMAGE_FIRST_SECTION(pNTHeaders);

		if(! (pFirstSecHeader == pFirstSecHeader_Verify) )
		{
			wprintf_s(L"Error calculating address of first section header.\n");
			return FALSE;
		}
	#endif

	PIMAGE_SECTION_HEADER pCurSecHeader = pFirstSecHeader;

	// 
	wprintf_s(L"\n* IMAGE_SECTION_HEADER *\n");
	wprintf_s(L"%-8s  %10s  %10s  %11s  %8s\n", L"Name", L"VirtAddr", L"PtrRawData", L"RawDataSize", L"VirtSize");
	for(DWORD i = 0; i < pNTHeaders->FileHeader.NumberOfSections; ++i, ++pCurSecHeader)
	{
		wprintf_s(L"%-8S  0x%08x  0x%08x  0x%08x  0x%08x\n", pCurSecHeader->Name, pCurSecHeader->VirtualAddress, 
			pCurSecHeader->PointerToRawData, pCurSecHeader->SizeOfRawData, pCurSecHeader->Misc.VirtualSize);

	}// for i

	return TRUE;
}// fDumpSectionHeaders()


// fFindIAT_InText()
// Find the starting address - virtual address and file pointer - and the 
// size of the IAT within the .text section if present.
BOOL fFindIAT_InText(HANDLE hFileBase, IMAGE_NT_HEADERS *pNTHeader,
    __out NONCODE_LOC *pNonCodeBlocks)
{
	ASSERT(hFileBase != NULL);
	ASSERT(pNTHeader != NULL && pNonCodeBlocks != NULL);

	// first find the virtual address and size of the imports section
	// from the DataDirectory
	//IMAGE_THUNK_DATA

	return TRUE;
}// fFindIAT_InText()

//
// ** Mostly from Matt Pietrek's PEDUMP.exe **
//
BOOL fDumpExports(DWORD dwFileBase, IMAGE_NT_HEADERS *pNTHeader, 
    IMAGE_DATA_DIRECTORY *pDataDir_Exp)
{
	ASSERT(pNTHeader != NULL && pDataDir_Exp != NULL);

	IMAGE_EXPORT_DIRECTORY *pExportDir = NULL;
	PIMAGE_SECTION_HEADER pExportsSecHeader = NULL;

	DWORD dwExportsBeginRVA = 0;
	DWORD dwExportsEndRVA = 0;

	INT delta = 0;
	PSTR filename;
	PDWORD functions;
    PWORD ordinals;
    PSTR *name;

    char szTimestampStr[STRLEN_CTIME];

	if(pDataDir_Exp->VirtualAddress == 0 || pDataDir_Exp->Size == 0)
	{
		wprintf_s(L"fDumpExports(): No Exports Found\n");
		return FALSE;
	}

	dwExportsBeginRVA = pDataDir_Exp->VirtualAddress;
	dwExportsEndRVA = pDataDir_Exp->VirtualAddress + pDataDir_Exp->Size;

	pExportsSecHeader = GetEnclosingSectionHeader(dwExportsBeginRVA, pNTHeader);

	delta = (INT)(pExportsSecHeader->VirtualAddress - pExportsSecHeader->PointerToRawData);

    pExportDir = (PIMAGE_EXPORT_DIRECTORY)( dwFileBase + (DWORD)(dwExportsBeginRVA - delta));
        
    filename = (PSTR)(pExportDir->Name - delta + dwFileBase);
	printf("Exports table:\n\n");
    printf("  Name:            %s\n", filename);
    printf("  Characteristics: %08X\n", pExportDir->Characteristics);
    printf("  TimeDateStamp:   %08X -> ", pExportDir->TimeDateStamp);
    if (ctime_s(szTimestampStr, _countof(szTimestampStr), (time_t*)&pExportDir->TimeDateStamp) == 0)
    {
        // Buffer returned from ctime_s() will have \n\0 at the end when successful
        wprintf_s(L"%S", szTimestampStr);
    }
    else
    {
        wprintf_s(L"\n");
    }
    
    printf("  Version:         %u.%02u\n", pExportDir->MajorVersion, pExportDir->MinorVersion);
    printf("  Ordinal base:    %08X\n", pExportDir->Base);
    printf("  # of functions:  %08X\n", pExportDir->NumberOfFunctions);
    printf("  # of Names:      %08X\n", pExportDir->NumberOfNames);
    
    functions = (PDWORD)((DWORD)pExportDir->AddressOfFunctions - delta + dwFileBase);
    ordinals = (PWORD)((DWORD)pExportDir->AddressOfNameOrdinals - delta + dwFileBase);
    name = (PSTR *)((DWORD)pExportDir->AddressOfNames - delta + dwFileBase);

    printf("\n  Entry Pt  Ordn  Name\n");
    for ( DWORD i=0; i < pExportDir->NumberOfFunctions; i++ )
    {
        DWORD entryPointRVA = functions[i];
        DWORD j;

        if ( entryPointRVA == 0 )   // Skip over gaps in exported function
            continue;               // ordinals (the entrypoint is 0 for
                                    // these functions).

        printf("  %08X  %4u", entryPointRVA, i + pExportDir->Base );

        // See if this function has an associated name exported for it.
        for ( j=0; j < pExportDir->NumberOfNames; j++ )
            if ( ordinals[j] == i )
                printf("  %s", name[j] - delta + dwFileBase);

        // Is it a forwarder?  If so, the entry point RVA is inside the
        // .edata section, and is an RVA to the DllName.EntryPointName
        if ( (entryPointRVA >= dwExportsBeginRVA)
             && (entryPointRVA <= dwExportsEndRVA) )
        {
            printf(" (forwarder -> %s)", (char*)(entryPointRVA - delta + dwFileBase) );
        }
        
        printf("\n");
    }

	return TRUE;

}// fDumpExports()
