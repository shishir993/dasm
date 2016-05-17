
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//

#include "DasmAssert.h"

void _Assert(char *pszMsg, unsigned uLine)
{
    fflush(NULL);        // ensure that all buffers are written out first
    fprintf(stderr, "Assertion failed in %s at Line %u\n", pszMsg, uLine);
    fflush(stderr);
    exit(1);

}// _Assert()
