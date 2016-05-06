
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#ifndef _SCAN_H
#define _SCAN_H

#include "DasmInc.h"
#include "Utils.h"

BOOL fBeginFileScan(HANDLE hFileView, BOOL *pf64bit);
BOOL fFindIAT_InText(HANDLE HFileBase, IMAGE_NT_HEADERS *pNTHeader, __out NONCODE_LOC *pNonCodeBlocks);
BOOL fDumpFileHeader(IMAGE_NT_HEADERS *pNTHeader, BOOL *pf64bit);
BOOL fDumpDataDirectory(IMAGE_NT_HEADERS *pNTHeader);
BOOL fDumpSectionHeaders(IMAGE_NT_HEADERS *pNTHeaders);
BOOL fDumpExports(DWORD dwFileBase, IMAGE_NT_HEADERS *pNTHeader, IMAGE_DATA_DIRECTORY *pDataDir_Exp);

#endif // _SCAN_H
