
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#ifndef _UTILS_H
#define _UTILS_H

#include "DasmInc.h"
#include "DASMEngine.h"

#define MOD_MASK    0xC0    // 1100 0000
#define REG_MASK    0x38    // 0011 1000
#define RM_MASK     0x07    // 0000 0111
#define DBIT_MASK   0x02    // 0000 0010
#define WBIT_MASK   0x01    // 0000 0001

/*
 * Utility functions provided
 */

 // Instruction utils
void Util_SplitModRMByte(BYTE bModRMValue, __out PBYTE pbMod,
    __out PBYTE pbReg, __out PBYTE pbRM);
void Util_GetDWBits(BYTE bOpcode, __out PBYTE pbDBit, __out PBYTE pbWBit);
BOOL Util_IsPrefix(BYTE bValue);

// PE header related utils
BOOL GetPtrToNTHeaders(HANDLE hFileView, __out IMAGE_NT_HEADERS **ppNTHeaders);
BOOL GetPtrToCode(DWORD dwFileBase, IMAGE_NT_HEADERS *pNTHeaders, __out DWORD *pdwCodePtr,
    __out DWORD *pdwSizeOfData, __out DWORD *pdwCodeSecVirtAddr);
PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader);
BOOL Util_DumpIMAGE_IMPORT_DESCRIPTORS(DWORD rva, DWORD dwSize, PIMAGE_NT_HEADERS pNTHeaders, DWORD dwFileBase);

// Other
void Util_TwosComplementByte(BYTE chSignedVal, __out PBYTE pchOut);
void Util_TwosComplementInt(INT iSignedVal, __out PINT piOut);

#endif // _UTILS_H
