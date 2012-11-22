
#ifndef _SCAN_H
#define _SCAN_H

#include <time.h>
#include "DasmInc.h"
#include "Utils.h"

BOOL fBeginFileScan(HANDLE hFile, HANDLE hFileMapObj,
					HANDLE hFileView);
BOOL fFindIAT_InText(HANDLE HFileBase, IMAGE_NT_HEADERS *pNTHeader,
					__out NONCODE_LOC *pNonCodeBlocks);
BOOL fDumpFileHeader(IMAGE_NT_HEADERS *pNTHeader);
BOOL fDumpDataDirectory(IMAGE_NT_HEADERS *pNTHeader);
BOOL fDumpSectionHeaders(IMAGE_NT_HEADERS *pNTHeaders);
BOOL fDumpExports(DWORD dwFileBase, IMAGE_NT_HEADERS *pNTHeader, 
		IMAGE_DATA_DIRECTORY *pDataDir_Exp);

#endif // _SCAN_H
