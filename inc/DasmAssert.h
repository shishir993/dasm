
// ---------------------------------------------------
// Author: Shishir Bhat (www.shishirbhat.com)
// The MIT License (MIT)
// Copyright (c) 2016
//


/***********************
* ASSERT(x) is a debug-mode-only macro that is used to catch errors that must not
* occur when software is released. It finds out bugs in the coding phase rather than
* the testing phase.
*
* ASSERT accepts a relational expression as a macro-argument and tests whether it is
* true. If it is true, nothing is done. If it is false, the user-defined _Assert()
* function is called which prints the line number and filename in which the assertion
* failed.
*
* Debug-mode-only is achieved using the #ifdef directive.
* Code is compiled using Visual Studio 2010, which defines the macro _DEBUG in debug-mode.
* In release-mode NDEBUG is defined.
* Your own macro can be defined in either of the modes by navigating to
* Project Properties > C/C++ > Preprocessor > Preprocessor definitions.
***********************/

#ifndef _ASSERT_H
#define _ASSERT_H

#include <stdio.h>
#include <stdlib.h>

#ifdef _DEBUG

void _Assert(char*, unsigned);
#define ASSERT(x)    \
        if(x) {}        \
        else            \
            _Assert(__FILE__, __LINE__)

#else

#define ASSERT(x)

#endif

#endif    // _ASSERT_H
