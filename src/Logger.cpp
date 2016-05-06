
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#include "Logger.h"
#include "DasmAssert.h"

void PrintDebugString(wchar_t const *pszFmt, ...)
{
    static wchar_t g_szBuffer[1024];

    HRESULT hr;
    va_list pArgs;

    va_start(pArgs, pszFmt);
    hr = StringCchVPrintf(g_szBuffer, ARRAYSIZE(g_szBuffer), pszFmt, pArgs);
    va_end(pArgs);

    if (FAILED(hr) && (hr != STRSAFE_E_INSUFFICIENT_BUFFER))
    {
        ASSERT(!L"StringCchVPrintf failed!");
        goto errExit;
    }

    OutputDebugString(g_szBuffer);
    return;

errExit:
    return;
}
