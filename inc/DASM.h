
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#ifndef _DASM_H
#define _DASM_H

#include "DasmInc.h"
#include "Scan.h"
#include "DasmEngine.h"
#include "Utils.h"

#define EXEFILEMAP_NAME L"InputFileMapName"

int wmain(int argc, WCHAR **argv);
BOOL CmdArgsHandler(int argc, WCHAR **argv, WCHAR *pwszInFile, DWORD dwInFileBufSize);
void RunTests();
BOOL OpenAndMapFile(WCHAR *pwszFilePath, HANDLE *hFile, HANDLE *hFileMapObj, HANDLE *hFileView);
BOOL CloseFile(HANDLE hFile, HANDLE hFileMapObj, HANDLE hFileView);

#endif // _DASM_H
