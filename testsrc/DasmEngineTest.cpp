
#include "testcommon.h"
#include "DasmEngine.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

// second opcode byte values
static BYTE g_abMMXOpcodes[] = {
    0x0F, 0x60,
    0x0F, 0x61,
    0x0F, 0x62,
    0x0F, 0x63,
    0x0F, 0x64,
    0x0F, 0x65,
    0x0F, 0x66,
    0x0F, 0x67,
    0x0F, 0x67,
    0x0F, 0x68,
    0x0F, 0x69,
    0x0F, 0x6A,
    0x0F, 0x6B,
    0x0F, 0x6E,
    0x0F, 0x6F,

    0x0F, 0x70,
    0x0F, 0x71,
    0x0F, 0x72,
    0x0F, 0x73,
    0x0F, 0x74,
    0x0F, 0x75,
    0x0F, 0x76,
    0x0F, 0x77,
    0x0F, 0x7E,
    0x0F, 0x7F,

    0x0F, 0xC4,
    0x0F, 0xC5,

    0x0F, 0xD1,
    0x0F, 0xD2,
    0x0F, 0xD3,
    0x0F, 0xD5,
    0x0F, 0xD7,
    0x0F, 0xD8,
    0x0F, 0xD9,
    0x0F, 0xDA,
    0x0F, 0xDB,
    0x0F, 0xDC,
    0x0F, 0xDD,
    0x0F, 0xDE,
    0x0F, 0xDF,

    0x0F, 0xE0,
    0x0F, 0xE1,
    0x0F, 0xE2,
    0x0F, 0xE3,
    0x0F, 0xE4,
    0x0F, 0xE5,
    0x0F, 0xE8,
    0x0F, 0xE9,
    0x0F, 0xEA,
    0x0F, 0xEB,
    0x0F, 0xEC,
    0x0F, 0xED,
    0x0F, 0xEE,
    0x0F, 0xEF,

    0x0F, 0xF1,
    0x0F, 0xF2,
    0x0F, 0xF3,
    0x0F, 0xF5,
    0x0F, 0xF6,
    0x0F, 0xF8,
    0x0F, 0xF9,
    0x0F, 0xFA,
    0x0F, 0xFC,
    0x0F, 0xFD,
    0x0F, 0xFE };

// second opcode byte values
static BYTE g_abSSEOpcodes[] = {
    0x0F, 0x10,
    0x0F, 0x11,
    0x0F, 0x12,
    0x0F, 0x13,
    0x0F, 0x14,
    0x0F, 0x15,
    0x0F, 0x16,
    0x0F, 0x17,

    0x0F, 0x28,
    0x0F, 0x29,
    0x0F, 0x2A,
    0x0F, 0x2B,
    0x0F, 0x2C,
    0x0F, 0x2D,
    0x0F, 0x2E,
    0x0F, 0x2F,

    0x0F, 0x50,
    0x0F, 0x51,
    0x0F, 0x52,
    0x0F, 0x53,
    0x0F, 0x54,
    0x0F, 0x55,
    0x0F, 0x56,
    0x0F, 0x57,
    0x0F, 0x58,
    0x0F, 0x59,
    0x0F, 0x5C,
    0x0F, 0x5D,
    0x0F, 0x5E,
    0x0F, 0x5F,

    0x0F, 0xAE,
    0x0F, 0xC2,
    0x0F, 0xC6,

    0x0F, 0xE7,
    0x0F, 0xF7 };

namespace dasm_utest {

TEST_CLASS(DasmEngineTests) {

public:
    TEST_METHOD(Test_FPU) {
        INT iOpcode;
        INT iModRM;
        // TODO: Change this to add Asserts
        wprintf_s(L"\n*************** RegEx ***************\n");

        for (iOpcode = 0xD8; iOpcode <= 0xDF; ++iOpcode) {
            bFullOpcode = (BYTE)iOpcode;
            bOpcodeLow = bFullOpcode & 0x0f;
            bOpcodeHigh = (bFullOpcode & 0xf0) >> 4;

            for (BYTE iReg = 0; iReg <= 7; ++iReg) {
                bFPUModRM = iReg;
                bFPUModRM = bFPUModRM << 3;
                OPCHndlrFPU_All(bFullOpcode);
            }

            wprintf_s(L"\n");
        }

        wprintf_s(L"\n*************** FullEx ***************\n");
        for (iOpcode = 0xD8; iOpcode <= 0xDF; ++iOpcode) {
            bFullOpcode = (BYTE)iOpcode;
            bOpcodeLow = bFullOpcode & 0x0f;
            bOpcodeHigh = (bFullOpcode & 0xf0) >> 4;

            for (iModRM = 0xC0; iModRM <= 0xFF; ++iModRM) {
                bFPUModRM = (BYTE)iModRM;
                OPCHndlrFPU_All(bFullOpcode);
            }
            wprintf_s(L"\n");
        }
    }

    TEST_METHOD(Test_MMX) {
        // TODO: Change this to add Asserts
        //BYTE *pCurOpcode = abMMXOpcodes;
        INT nOpcodes = _countof(g_abMMXOpcodes) / 2;
        for (INT i = 0; i < nOpcodes; ++i) {
            pByteInCode = g_abMMXOpcodes + i * 2;
            StateOpcode();
        }
    }

    TEST_METHOD(Test_SSE) {
        // TODO: Change this to add Asserts
        //BYTE *pCurOpcode = g_abSSEOpcodes;
        INT nOpcodes = _countof(g_abSSEOpcodes) / 2;
        for (INT i = 0; i < nOpcodes; ++i) {
            pByteInCode = g_abSSEOpcodes + i * 2;
            StateOpcode();
        }
    }
};
}
