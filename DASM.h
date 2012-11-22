
#ifndef _DASM_H
#define _DASM_H

#include "DasmInc.h"
#include "Scan.h"
#include "DasmEngine.h"
#include "Utils.h"

#define EXEFILEMAP_NAME L"InputFileMapName"

int wmain(int argc, WCHAR **argv);
BOOL fCmdArgsHandler(int argc, WCHAR **argv, WCHAR *pwszInFile,
					DWORD dwInFileBufSize);
void vRunTests();
BOOL fOpenAndMapFile(WCHAR *pwszFilePath, HANDLE *hFile, HANDLE *hFileMapObj,
						HANDLE *hFileView);
BOOL fCloseFile(HANDLE hFile, HANDLE hFileMapObj,
					HANDLE hFileView);

#endif // _DASM_H