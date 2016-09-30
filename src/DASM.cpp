
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#include "DASM.h"

// global variables
DWORD g_dwInputFileType;    // set by fBeginFileScan()
BINFILEINFO g_binFileInfo;

// ** Controlling program options **
// true by default
BOOL g_fHeaders = TRUE;    // NTHeaders, FileHeader, Optional Header
BOOL g_fDisasm = TRUE;

// false by default
BOOL g_fExports;
BOOL g_fImports;

int wmain(int argc, WCHAR **argv) {
    WCHAR wszFilepath[MAX_PATH + 1] = L"";
    WCHAR wszOutFile[MAX_PATH + 1] = L"";

    HANDLE hFile = NULL, hFileObj = NULL, hFileView = NULL;
    DWORD dwCodeSecOffset = 0;
    DWORD dwSizeOfCodeSection = 0;

    BOOL f64bit = FALSE;

    logdbg(L"Disassembler started: %s", L"hello,world!");

#ifdef NDEBUG
    // Opening statement
    wprintf(L"Shishir's Garage project::DASM v%s, a disassembler for 32bit PE files\n"
        L"Coder: Shishir Bhat {shishir89@gmail.com, www.shishirbhat.com}\n"
        L"Copyright: MIT License (MIT) (Don't forget to include my name as a reference"
        L" in your code/webpage :))\n\n", DASM_VERSION_STR);
#endif

    int iRetVal = 0;
    __try {

        if (!CmdArgsHandler(argc, argv, wszFilepath, _countof(wszFilepath))) {
            wprintf_s(L"main(): Unable to parse command line arguments\n");
            wprintf_s(L"usage: %s\n\t[inputFile]\n\t[-exports|-e]\n\t[-imports|-i]\n\t[-headers|-h]\n\t[-disasm|-d]\n", argv[0]);
            iRetVal = 1;
            __leave;
        }

        if (!OpenAndMapFile(wszFilepath, &hFile, &hFileObj, &hFileView)) {
            wprintf_s(L"Error opening input file\n");
            iRetVal = 2;
            __leave;
        }

        wprintf_s(L"********************************\nDisassembling file: %s\n", wszFilepath);

        // dump information from headers
        if (!BeginFileScan(hFileView, &f64bit)) {
            wprintf_s(L"main(): fBeginFileScan() error\n");
            iRetVal = 3;
            __leave;
        }

        if (g_fDisasm) {
            // get pointer to code section
            if (!GetPtrToCode((DWORD)hFileView, g_binFileInfo.pNTHeaders,
                &dwCodeSecOffset, &dwSizeOfCodeSection, &g_binFileInfo.dwVirtBaseOfCode)) {
                wprintf_s(L"Cannot retrieve pointer to code section. Aborting...\n");
                iRetVal = 4;
                __leave;
            }

            DoDisassembly((DWORD*)dwCodeSecOffset, dwSizeOfCodeSection, g_binFileInfo.dwVirtBaseOfCode, f64bit);
        }
    }
    __finally {
        if (hFile != NULL && hFileObj != NULL && hFileView != NULL) {
            CloseFile(hFile, hFileObj, hFileView);
        }
    }
    return iRetVal;
}

BOOL CmdArgsHandler(int argc, WCHAR **argv, WCHAR *pwszInFile, DWORD dwInFileBufSize) {
    BOOL fInFile = FALSE;

    BOOL fLocHeaders = FALSE;
    BOOL fLocDisasm = FALSE;

    HRESULT hRes;

    while (--argc > 0) {
        if (wcscmp(argv[argc], L"/exports") == 0 ||
            wcscmp(argv[argc], L"/e") == 0) {
            g_fExports = TRUE;
        }
        else if (wcscmp(argv[argc], L"/imports") == 0 ||
            wcscmp(argv[argc], L"/i") == 0) {
            g_fImports = TRUE;
        }
        else if (wcscmp(argv[argc], L"/headers") == 0 ||
            wcscmp(argv[argc], L"/h") == 0) {
            fLocHeaders = TRUE;
        }
        else if (wcscmp(argv[argc], L"/disasm") == 0 ||
            wcscmp(argv[argc], L"/d") == 0) {
            fLocDisasm = TRUE;
        }
        else {
            // must be the input file
            hRes = StringCchCopy(pwszInFile, dwInFileBufSize, argv[argc]);

            fInFile = TRUE;

            if (FAILED(hRes)) {
                wprintf_s(L"CmdArgsHandler(): Unable to copy input file %s into buffer\n", argv[argc]);
                return FALSE;
            }
        }// if-else
    }// while()

    // Check if we have to turn off the defaults
    if ((g_fImports || g_fExports || fLocDisasm) && (!fLocHeaders)) {
        g_fHeaders = FALSE;
    }

    if ((g_fImports || g_fExports || fLocHeaders) && (!fLocDisasm)) {
        g_fDisasm = FALSE;
    }

    if (!fInFile) {
        wprintf_s(L"File to disassemble? : ");
        if (wscanf_s(L"%s", pwszInFile, dwInFileBufSize) == EOF) {
            logdbg(L"CmdArgsHandler(): Unable to read input file path");
            return FALSE;
        }
    }

    return TRUE;
}

BOOL OpenAndMapFile(WCHAR *pwszFilePath, HANDLE *hFile, HANDLE *hFileMapObj, HANDLE *hFileView) {
    DWORD dwRetVal = 0;
    DWORD dwFileSize = 0;

    // try to open the file
    *hFile = CreateFile(pwszFilePath,
        GENERIC_READ | GENERIC_EXECUTE,
        0, NULL,    // no sharing, NULL security desc
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (*hFile == INVALID_HANDLE_VALUE) {
        DWORD dwError = GetLastError();
        DBG_UNREFERENCED_LOCAL_VARIABLE(dwError);
        return FALSE;
    }

    if ((dwRetVal = GetFileSize(*hFile, &dwFileSize)) == INVALID_FILE_SIZE) {
        DWORD dwError = GetLastError();
        DBG_UNREFERENCED_LOCAL_VARIABLE(dwError);
        return FALSE;
    }

    if (dwRetVal == 0 && dwFileSize == 0) {
        wprintf(L"Zero file size\n");
        return FALSE;
    }

    // create a memory mapping for the file with GENERIC_READ and GENERIC_EXECUTE
    // that is, create the file mapping object
    if ((*hFileMapObj = CreateFileMapping(*hFile, NULL, PAGE_EXECUTE_READ, 0, 0, EXEFILEMAP_NAME)) == NULL) {
        CloseHandle(*hFile);
        return FALSE;
    }

    // check for ERROR_ALREADY_EXISTS ??

    // map this file mapping object into our address space
    if ((*hFileView = MapViewOfFile(*hFileMapObj, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0)) == NULL) {
        dwRetVal = GetLastError();
        CloseHandle(*hFileMapObj);
        CloseHandle(*hFile);
        return FALSE;
    }

    return TRUE;
}

BOOL CloseFile(HANDLE hFile, HANDLE hFileMapObj, HANDLE hFileView) {
    UnmapViewOfFile(hFileView);
    CloseHandle(hFileMapObj);
    CloseHandle(hFile);
    return TRUE;
}
