
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#ifndef _DASM_LOGGER_H
#define _DASM_LOGGER_H

#include <Windows.h>
#include <strsafe.h>

#ifdef _DEBUG
#define logdbg(fmt, ...)    PrintDebugString(L"[%s:%d] " fmt L"\n", __FUNCTIONW__, __LINE__, ##__VA_ARGS__)
#else
#define logdbg(fmt, ...)
#endif

void PrintDebugString(wchar_t const *pszFmt, ...);

#endif // _DASM_LOGGER_H
