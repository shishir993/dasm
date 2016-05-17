
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#include "Utils.h"


/* Util_fSplitModRMByte()
 * Given the ModR/M byte value, returns the individual fields:
 * Mod, Reg/Opcode and R/M via pointers to byte variables.
 * If any of the __out pointers are NULL, then those fields
 * are not computed.
 *
 *    **** This function is also used to spli the SIB byte ****
 *    ModRM and SIB have the same structure!
 *
 * Args:
 *        bModRMValue: BYTE: value of the ModR/M byte.
 *        pbMod: PBYTE: Address in which to store the Mod field value.
 *        pbReg: PBYTE: Address in which to store the Reg/Opcode field value.
 *        pbRM: PBYTE: Address in which to store the R/M field value.
 *
 * RetVal:
 *        none
 */
void Util_vSplitModRMByte(BYTE bModRMValue, __out PBYTE pbMod,
    __out PBYTE pbReg, __out PBYTE pbRM)
{
    //    Bits:    7 6   5 4 3   2 1 0
    //    Field:    Mod    Reg     R/M
    if (pbMod)
        *pbMod = (bModRMValue & MOD_MASK) >> 6;

    if (pbReg)
        *pbReg = (bModRMValue & REG_MASK) >> 3;

    if (pbRM)
        *pbRM = bModRMValue & RM_MASK;

    return;

}// Util_fSplitModRMByte


/* Util_vGetDWBits()
 * Given the opcode byte, returns the value of the d and w bits
 * of the opcode. If any of the __out pointers are NULL, then
 * those fields are not computed.
 *
 * Args:
 *        bOpcode: BYTE: value of the opcode byte.
 *        pbDBit: PBYTE: Address in which to store the D-bit value.
 *        pbWBit: PBYTE: Address in which to store the W-bit value.
 *
 * RetVal:
 *        none
 */
void Util_vGetDWBits(BYTE bOpcode, __out PBYTE pbDBit, __out PBYTE pbWBit)
{
    if (pbDBit)
        *pbDBit = (bOpcode & DBIT_MASK) >> 1;

    if (pbWBit)
        *pbWBit = bOpcode & WBIT_MASK;

    return;

}// Util_vGetDWBits()


/* Util_fIsPrefix()
 * Given a byte as argument, tells whether it is a valid prefix or not.
 *
 * Args:
 *        bValue: BYTE: value to be checked.
 *
 * RetVal:
 *        TRUE/FALSE depending on whether bValue is a prefix or not.
 */
BOOL Util_fIsPrefix(BYTE bValue)
{
    switch (bValue)
    {
    case OPC_PREFIX_SEGOVR_ES:
    case OPC_PREFIX_SEGOVR_CS:
    case OPC_PREFIX_SEGOVR_SS:
    case OPC_PREFIX_SEGOVR_DS:
    case OPC_PREFIX_SEGOVR_FS:
    case OPC_PREFIX_SEGOVR_GS:
    case OPC_PREFIX_OPSIZE:
    case OPC_PREFIX_ADSIZE:
    case OPC_PREFIX_LOCK:
    case OPC_PREFIX_REPNE:
    case OPC_PREFIX_REPE:
        return TRUE;

    default:
        break;
    }// switch(bValue)

    return FALSE;

}// Util_fIsPrefix()


/* fGetPtrNTHeaders()
 *
 *
 * Args:
 *
 *
 * RetVal:
 *
 */
BOOL fGetPtrNTHeaders(HANDLE hFileView, __out IMAGE_NT_HEADERS **ppNTHeaders)
{
    ASSERT(hFileView != NULL && ppNTHeaders != NULL);

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hFileView;

    *ppNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
    return TRUE;

}// fGetPtrNTHeaders()


/* fGetPtrToCode()
 *
 *
 * Args:
 *
 *
 * RetVal:
 *
 */
BOOL fGetPtrToCode(DWORD dwFileBase, IMAGE_NT_HEADERS *pNTHeaders,
    __out DWORD *pdwCodePtr, __out DWORD *pdwSizeOfData, __out DWORD *pdwCodeSecVirtAddr)
{
    ASSERT(pNTHeaders != NULL && pdwCodePtr != NULL);
    ASSERT(pdwSizeOfData != NULL);

    PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
    DWORD dwSecChars = 0;

    // Get the .text section's header using AddressOfEntryPoint as the RVA
    if ((pImgSecHeader = GetEnclosingSectionHeader(pNTHeaders->OptionalHeader.AddressOfEntryPoint,
        pNTHeaders)) == NULL)
    {
        wprintf_s(L"fGetPtrToCode(): pImgSecHeader NULL\n");
        return FALSE;
    }
    dwSecChars = pImgSecHeader->Characteristics;

    // test if the retrieved section contains code and is executable
    if (!((dwSecChars & IMAGE_SCN_CNT_CODE) &&
        (dwSecChars & IMAGE_SCN_MEM_EXECUTE)))
    {
        wprintf_s(L"Retrieved section header %S but does not contain code or is not executable\n",
            (char*)pImgSecHeader->Name);
        return FALSE;
    }

    *pdwCodePtr = dwFileBase + pImgSecHeader->PointerToRawData;

    // From "Microsoft Portable Executable and Common Object File Format Specification"
    // todo: If SizeOfRawData is less than VirtualSize, the remainder of the section is zero-filled.
    // done: 081812
    if (pImgSecHeader->SizeOfRawData < pImgSecHeader->Misc.VirtualSize)
    {
        *pdwSizeOfData = pImgSecHeader->SizeOfRawData;
    }
    else
    {
        *pdwSizeOfData = pImgSecHeader->Misc.VirtualSize;
    }

    //*pdwSizeOfData = pImgSecHeader->SizeOfRawData;
    *pdwCodeSecVirtAddr = pNTHeaders->OptionalHeader.ImageBase + pImgSecHeader->VirtualAddress;

    return TRUE;
}// fGetPtrToCode()


/* GetEnclosingSectionHeader()
 * ** From Matt Pietrek's PEDUMP.exe **
 * Given an RVA, look up the section header that encloses it and return a
 * pointer to its IMAGE_SECTION_HEADER.
 *
 * Args:
 *
 *
 * RetVal:
 *
 */
PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;

    for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
    {
        // Is the RVA within this section?
        if ((rva >= section->VirtualAddress) &&
            (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
        {
            return section;
        }
    }

    return NULL;
}

// Notes: Under construction
BOOL Util_fDumpIMAGE_IMPORT_DESCRIPTORS(DWORD rva, DWORD dwSize, PIMAGE_NT_HEADERS pNTHeaders, DWORD dwFileBase)
{
    PIMAGE_SECTION_HEADER pImgSecHeader = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImports = NULL;

    INT iFilePtrRVADelta = 0;

    WCHAR wszTimeStamp[32];

    // First get the file pointer of the first IMAGE_IMPORT_DESCRIPTOR
    if ((pImgSecHeader = GetEnclosingSectionHeader(rva, pNTHeaders)) == NULL)
    {
        wprintf_s(L"fDumpIMAGE_IMPORT_DESCRIPTOR(): Unable to retrieve section header\n");
        wprintf_s(L"rva = 0x%xh, dwSize = 0x%xh, pNTHeaders = %p, dwFileBase = 0x%08xh\n",
            rva, dwSize, pNTHeaders, dwFileBase);
        return FALSE;
    }

    iFilePtrRVADelta = (INT)(pImgSecHeader->PointerToRawData - pImgSecHeader->VirtualAddress);

    // find the Imports within the section
    pImports = (PIMAGE_IMPORT_DESCRIPTOR)(rva + iFilePtrRVADelta + dwFileBase);

    wprintf_s(L"\n** IMAGE_IMPORT_DESCRIPTOR **\n");

    while (pImports->Characteristics != 0 || pImports->FirstThunk != 0 ||
        pImports->ForwarderChain != 0 || pImports->Name != 0 ||
        pImports->OriginalFirstThunk != 0 || pImports->TimeDateStamp != 0)
    {
        wprintf_s(L"Entry:\n");
        wprintf_s(L"    Char/OrigFirstThunk: %x\n", pImports->OriginalFirstThunk);
        if (pImports->TimeDateStamp != 0 &&
            _wctime_s(wszTimeStamp, _countof(wszTimeStamp), (time_t*)&pImports->TimeDateStamp) == 0)
        {
            wprintf_s(L"    TimeDateStamp:       %xh %s\n", pImports->TimeDateStamp, wszTimeStamp);
        }
        wprintf_s(L"    ForwarderChain:      %xh\n", pImports->ForwarderChain);
        if (pImports->Name)
        {
            wprintf_s(L"    Name:                %S\n", (char*)pImports->Name + iFilePtrRVADelta + dwFileBase);
        }
        wprintf_s(L"    FirstThunk:          %xh\n", pImports->FirstThunk);
        wprintf_s(L"    IAT:\n");

        PIMAGE_THUNK_DATA pImgThunkData = (PIMAGE_THUNK_DATA)(pImports->FirstThunk + iFilePtrRVADelta + dwFileBase);

        // Dump the IAT
        {
            while (pImgThunkData->u1.AddressOfData != 0)
            {
                wprintf_s(L"        -> ");

                // If the high bit is set, the bottom 31bits is treated as the ordinal value
                if (pImgThunkData->u1.AddressOfData & 0x80000000)
                {
                    wprintf_s(L"Ordinal: %08x\n", IMAGE_ORDINAL(pImgThunkData->u1.Ordinal));
                }
                else
                {
                    // IMAGE_THUNK_ DATA value is an RVA to the IMAGE_IMPORT_BY_NAME
                    PIMAGE_IMPORT_BY_NAME pImpByName = (PIMAGE_IMPORT_BY_NAME)(pImgThunkData->u1.AddressOfData +
                        iFilePtrRVADelta + dwFileBase);
                    wprintf_s(L"Hint: %4u Name: %S\n", pImpByName->Hint, (char*)pImpByName->Name);
                }

                ++pImgThunkData;

            }// while(pImgThunkData->u1 != 0)
        }// IAT block

        wprintf_s(L"\n");

        ++pImports;// += sizeof(IMAGE_IMPORT_DESCRIPTOR);

    }

    return TRUE;
}


void Util_vTwosComplementByte(BYTE chSignedVal, __out PBYTE pchOut)
{
    __asm {
        push eax
        push ebx
        xor eax, eax
        mov al, chSignedVal
        not al
        add al, 1
        mov ebx, pchOut
        mov byte ptr[ebx], al
        pop ebx
        pop eax
    }

    return;
}


void Util_vTwosComplementInt(INT iSignedVal, __out PINT piOut)
{
    __asm {
        push eax
        push ebx
        xor eax, eax
        mov eax, iSignedVal
        not eax
        add eax, 1
        mov ebx, piOut
        mov dword ptr[ebx], eax
        pop ebx
        pop eax
    }

    return;
}
