
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

int wmain(int argc, WCHAR **argv)
{

#ifdef UNIT_TESTS_ONLY
    DBG_UNREFERENCED_PARAMETER(argc);
    DBG_UNREFERENCED_PARAMETER(argv);
    RunTests();
    DEngine_FPUUnitTest();
    //DEngine_MMXUnitTest();
    DEngine_SSEUnitTest();
    return 0;
#else

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
            L"Copyright: MIT License (MIT) (Don't forget to include my name as a reference in your code/webpage :))\n\n", DASM_VERSION_STR);
#endif

    if (!CmdArgsHandler(argc, argv, wszFilepath, _countof(wszFilepath)))
    {
        wprintf_s(L"main(): Unable to parse command line arguments\n");
        wprintf_s(L"usage: %s\n\t[inputFile]\n\t[-exports|-e]\n\t[-imports|-i]\n\t[-headers|-h]\n\t[-disasm|-d]\n", argv[0]);
        return 1;
    }

    if (!OpenAndMapFile(wszFilepath, &hFile, &hFileObj, &hFileView))
    {
        wprintf_s(L"Error opening input file\n");
        return 1;
    }

    wprintf_s(L"********************************\nDisassembling file: %s\n", wszFilepath);

    __try
    {
        // dump information from headers
        if (!BeginFileScan(hFileView, &f64bit))
        {
            wprintf_s(L"main(): fBeginFileScan() error\n");
            return 1;
        }

        if (g_fDisasm)
        {
            // get pointer to code section
            if (!GetPtrToCode((DWORD)hFileView, g_binFileInfo.pNTHeaders,
                &dwCodeSecOffset, &dwSizeOfCodeSection, &g_binFileInfo.dwVirtBaseOfCode))
            {
                wprintf_s(L"Cannot retrieve pointer to code section. Aborting...\n");
                return 1;
            }

            DoDisassembly((DWORD*)dwCodeSecOffset, dwSizeOfCodeSection, g_binFileInfo.dwVirtBaseOfCode, f64bit);
        }// if(g_fDisasm)

        return 0;
    }
    __finally
    {
        if (hFile != NULL && hFileObj != NULL && hFileView != NULL)
        {
            CloseFile(hFile, hFileObj, hFileView);
        }
    }

#endif    // UNIT_TESTS_ONLY

}// wmain()


BOOL CmdArgsHandler(int argc, WCHAR **argv, WCHAR *pwszInFile,
    DWORD dwInFileBufSize)
{
    BOOL fInFile = FALSE;

    BOOL fLocHeaders = FALSE;
    BOOL fLocDisasm = FALSE;

    HRESULT hRes;

    while (--argc > 0)
    {
        if (wcscmp(argv[argc], L"/exports") == 0 ||
            wcscmp(argv[argc], L"/e") == 0)
        {
            g_fExports = TRUE;
        }
        else if (wcscmp(argv[argc], L"/imports") == 0 ||
            wcscmp(argv[argc], L"/i") == 0)
        {
            g_fImports = TRUE;
        }
        else if (wcscmp(argv[argc], L"/headers") == 0 ||
            wcscmp(argv[argc], L"/h") == 0)
        {
            fLocHeaders = TRUE;
        }
        else if (wcscmp(argv[argc], L"/disasm") == 0 ||
            wcscmp(argv[argc], L"/d") == 0)
        {
            fLocDisasm = TRUE;
        }
        else
        {
            // must be the input file
            hRes = StringCchCopy(pwszInFile, dwInFileBufSize, argv[argc]);

            fInFile = TRUE;

            if (FAILED(hRes))
            {
                wprintf_s(L"CmdArgsHandler(): Unable to copy input file %s into buffer\n", argv[argc]);
                return FALSE;
            }
        }// if-else
    }// while()

    // Check if we have to turn off the defaults
    if ((g_fImports || g_fExports || fLocDisasm) && (!fLocHeaders))
    {
        g_fHeaders = FALSE;
    }

    if ((g_fImports || g_fExports || fLocHeaders) && (!fLocDisasm))
    {
        g_fDisasm = FALSE;
    }

    if (!fInFile)
    {
        wprintf_s(L"File to disassemble? : ");
        if (wscanf_s(L"%s", pwszInFile, dwInFileBufSize) == EOF)
        {
            logdbg(L"CmdArgsHandler(): Unable to read input file path");
            return FALSE;
        }
    }

    return TRUE;

}// CmdArgsHandler()


BOOL OpenAndMapFile(WCHAR *pwszFilePath, HANDLE *hFile, HANDLE *hFileMapObj, HANDLE *hFileView)
{
    DWORD dwRetVal = 0;
    DWORD dwFileSize = 0;

    // try to open the file
    *hFile = CreateFile(pwszFilePath,
        GENERIC_READ | GENERIC_EXECUTE,
        0, NULL,    // no sharing, NULL security desc
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (*hFile == INVALID_HANDLE_VALUE)
    {
        DWORD dwError = GetLastError();
        DBG_UNREFERENCED_LOCAL_VARIABLE(dwError);
        return FALSE;
    }

    if ((dwRetVal = GetFileSize(*hFile, &dwFileSize)) == INVALID_FILE_SIZE)
    {
        DWORD dwError = GetLastError();
        DBG_UNREFERENCED_LOCAL_VARIABLE(dwError);
        return FALSE;
    }

    if (dwRetVal == 0 && dwFileSize == 0)
    {
        MessageBox(NULL, L"Zero file size\n", L"Error", MB_ICONERROR);
        return FALSE;
    }

    // create a memory mapping for the file with GENERIC_READ and GENERIC_EXECUTE
    // that is, create the file mapping object
    if ((*hFileMapObj = CreateFileMapping(*hFile, NULL, PAGE_EXECUTE_READ, 0, 0, EXEFILEMAP_NAME)) == NULL)
    {
        CloseHandle(*hFile);
        return FALSE;
    }

    // check for ERROR_ALREADY_EXISTS ??

    // map this file mapping object into our address space
    if ((*hFileView = MapViewOfFile(*hFileMapObj, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0)) == NULL)
    {
        dwRetVal = GetLastError();
        CloseHandle(*hFileMapObj);
        CloseHandle(*hFile);
        return FALSE;
    }

    return TRUE;
}// OpenAndMapFile()

BOOL CloseFile(HANDLE hFile, HANDLE hFileMapObj, HANDLE hFileView)
{
    UnmapViewOfFile(hFileView);
    CloseHandle(hFileMapObj);
    CloseHandle(hFile);

    return TRUE;

}// CloseFile()


// Unit testing of individual functions
void RunTests()
{
    // Util_SplitModRMByte()
    BYTE bModRM;
    BYTE bMod;
    BYTE bReg;
    BYTE bRM;

    bModRM = 0x7c;    // 01 111 100
    bMod = bReg = bRM = 0xff;
    Util_SplitModRMByte(bModRM, &bMod, &bReg, &bRM);
    if (bMod != 1 || bReg != 7 || bRM != 4)
        wprintf_s(L"!FAILED: Util_SplitModRMByte(): %x, %x, %x, %x\n",
            bModRM, bMod, bReg, bRM);
    else
        wprintf_s(L"*Passed: Util_SplitModRMByte(): %x, %x, %x, %x\n",
            bModRM, bMod, bReg, bRM);

    bModRM = 0xff;    // 11 111 111
    bMod = bReg = bRM = 0;
    Util_SplitModRMByte(bModRM, &bMod, &bReg, &bRM);
    if (bMod != 3 || bReg != 7 || bRM != 7)
        wprintf_s(L"!FAILED: Util_SplitModRMByte(): %x, %x, %x, %x\n",
            bModRM, bMod, bReg, bRM);
    else
        wprintf_s(L"*Passed: Util_SplitModRMByte(): %x, %x, %x, %x\n",
            bModRM, bMod, bReg, bRM);

    // test Util_GetDWBits()
    BYTE bD;
    BYTE bW;

    Util_GetDWBits(0x00, &bD, &bW);
    if (bD != 0 || bW != 0)
        wprintf_s(L"!FAILED: Util_GetDWBits(): %x, %x, %x\n", 0x00, bD, bW);
    else
        wprintf_s(L"*Passed: Util_GetDWBits(): %x, %x, %x\n", 0x00, bD, bW);

    Util_GetDWBits(0x03, &bD, &bW);
    if (bD != 1 || bW != 1)
        wprintf_s(L"!FAILED: Util_GetDWBits(): %x, %x, %x\n", 0x03, bD, bW);
    else
        wprintf_s(L"*Passed: Util_GetDWBits(): %x, %x, %x\n", 0x03, bD, bW);

    Util_GetDWBits(0x01, &bD, &bW);
    if (bD != 0 || bW != 1)
        wprintf_s(L"!FAILED: Util_GetDWBits(): %x, %x, %x\n", 0x01, bD, bW);
    else
        wprintf_s(L"*Passed: Util_GetDWBits(): %x, %x, %x\n", 0x01, bD, bW);

    Util_GetDWBits(0x02, &bD, &bW);
    if (bD != 1 || bW != 0)
        wprintf_s(L"!FAILED: Util_GetDWBits(): %x, %x, %x\n", 0x02, bD, bW);
    else
        wprintf_s(L"*Passed: Util_GetDWBits(): %x, %x, %x\n", 0x02, bD, bW);

    /*
     * Util_TwosComplementByte()
     */
    BYTE ch = 0xe8;
    BYTE chCompl;    // 2's complement(ch)
    Util_TwosComplementByte(ch, &chCompl);
    if (chCompl != 0x18)
        wprintf_s(L"!FAILED: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);

    ch = 0x00;
    Util_TwosComplementByte(ch, &chCompl);
    if (chCompl != 0x00)
        wprintf_s(L"!FAILED: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);

    ch = 0x7f;
    Util_TwosComplementByte(ch, &chCompl);
    if (chCompl != (BYTE)0x81)
        wprintf_s(L"!FAILED: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);

    ch = 0xff;
    Util_TwosComplementByte(ch, &chCompl);
    if (chCompl != 0x01)
        wprintf_s(L"!FAILED: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementByte(): %x, %x\n", ch, chCompl);

    /*
     * Util_TwosComplementInt()
     */
    INT i = 0x002b34e8;
    INT iCompl;    // 2's complement(ch)
    INT iTemp;

    iTemp = ((i ^ 0xffffffff) + 1);
    Util_TwosComplementInt(i, &iCompl);
    if (iCompl != iTemp)
        wprintf_s(L"!FAILED: Util_TwosComplementInt(): %x, %x\n", i, iCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementInt(): %x, %x\n", i, iCompl);

    i = 0x00;
    iTemp = ((i ^ 0xffffffff) + 1);
    Util_TwosComplementInt(i, &iCompl);
    if (iCompl != iTemp)
        wprintf_s(L"!FAILED: Util_TwosComplementInt(): %x, %x\n", i, iCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementInt(): %x, %x\n", i, iCompl);

    i = 0x7fffffff;
    iTemp = ((i ^ 0xffffffff) + 1);
    Util_TwosComplementInt(i, &iCompl);
    if (iCompl != iTemp)
        wprintf_s(L"!FAILED: Util_TwosComplementInt(): %x, %x\n", i, iCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementInt(): %x, %x\n", i, iCompl);

    i = 0xffffffff;
    iTemp = ((i ^ 0xffffffff) + 1);
    Util_TwosComplementInt(i, &iCompl);
    if (iCompl != iTemp)
        wprintf_s(L"!FAILED: Util_TwosComplementInt(): %x, %x\n", i, iCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementInt(): %x, %x\n", i, iCompl);

    i = 0x8b00401b;
    iTemp = ((i ^ 0xffffffff) + 1);
    Util_TwosComplementInt(i, &iCompl);
    if (iCompl != iTemp)
        wprintf_s(L"!FAILED: Util_TwosComplementInt(): %x, %x\n", i, iCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementInt(): %x, %x\n", i, iCompl);

    i = 0x80000000;
    iTemp = ((i ^ 0xffffffff) + 1);
    Util_TwosComplementInt(i, &iCompl);
    if (iCompl != iTemp)
        wprintf_s(L"!FAILED: Util_TwosComplementInt(): %x, %x\n", i, iCompl);
    else
        wprintf_s(L"*Passed: Util_TwosComplementInt(): %x, %x\n", i, iCompl);

}// RunTests()
