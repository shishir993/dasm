
#include "testcommon.h"
#include "Utils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace dasm_utest {

TEST_CLASS(UtilTests) {

public:
    TEST_METHOD(Test_SplitModRMByte) {
        BYTE bModRM;
        BYTE bMod;
        BYTE bReg;
        BYTE bRM;

        bModRM = 0x7c;    // 01 111 100
        bMod = bReg = bRM = 0xff;
        Util_SplitModRMByte(bModRM, &bMod, &bReg, &bRM);
        Assert::AreEqual((BYTE)0x1, bMod);
        Assert::AreEqual((BYTE)0x7, bReg);
        Assert::AreEqual((BYTE)0x4, bRM);

        bModRM = 0xff;    // 11 111 111
        bMod = bReg = bRM = 0;
        Util_SplitModRMByte(bModRM, &bMod, &bReg, &bRM);
        Assert::AreEqual((BYTE)0x3, bMod);
        Assert::AreEqual((BYTE)0x7, bReg);
        Assert::AreEqual((BYTE)0x7, bRM);
    }

    TEST_METHOD(Test_GetDWBits) {
        BYTE bD;
        BYTE bW;

        Util_GetDWBits(0x00, &bD, &bW);
        Assert::AreEqual((BYTE)0x0, bD);
        Assert::AreEqual((BYTE)0x0, bW);

        Util_GetDWBits(0x03, &bD, &bW);
        Assert::AreEqual((BYTE)0x1, bD);
        Assert::AreEqual((BYTE)0x1, bW);

        Util_GetDWBits(0x01, &bD, &bW);
        Assert::AreEqual((BYTE)0x0, bD);
        Assert::AreEqual((BYTE)0x1, bW);

        Util_GetDWBits(0x02, &bD, &bW);
        Assert::AreEqual((BYTE)0x1, bD);
        Assert::AreEqual((BYTE)0x0, bW);
    }

    TEST_METHOD(Test_TwosComplementByte) {
        BYTE ch = 0xe8;
        BYTE chCompl;    // 2's complement(ch)
        Util_TwosComplementByte(ch, &chCompl);
        Assert::AreEqual((BYTE)0x18, chCompl);

        ch = 0x00;
        Util_TwosComplementByte(ch, &chCompl);
        Assert::AreEqual((BYTE)0x0, chCompl);

        ch = 0x7f;
        Util_TwosComplementByte(ch, &chCompl);
        Assert::AreEqual((BYTE)0x81, chCompl);

        ch = 0xff;
        Util_TwosComplementByte(ch, &chCompl);
        Assert::AreEqual((BYTE)0x01, chCompl);
    }

    TEST_METHOD(Test_TwosComplementInt) {
        INT i = 0x002b34e8;
        INT iCompl;    // 2's complement(ch)
        INT iTemp;

        iTemp = ((i ^ 0xffffffff) + 1);
        Util_TwosComplementInt(i, &iCompl);
        Assert::AreEqual(iTemp, iCompl);

        i = 0x00;
        iTemp = ((i ^ 0xffffffff) + 1);
        Util_TwosComplementInt(i, &iCompl);
        Assert::AreEqual(iTemp, iCompl);

        i = 0x7fffffff;
        iTemp = ((i ^ 0xffffffff) + 1);
        Util_TwosComplementInt(i, &iCompl);
        Assert::AreEqual(iTemp, iCompl);

        i = 0xffffffff;
        iTemp = ((i ^ 0xffffffff) + 1);
        Util_TwosComplementInt(i, &iCompl);
        Assert::AreEqual(iTemp, iCompl);

        i = 0x8b00401b;
        iTemp = ((i ^ 0xffffffff) + 1);
        Util_TwosComplementInt(i, &iCompl);
        Assert::AreEqual(iTemp, iCompl);

        i = 0x80000000;
        iTemp = ((i ^ 0xffffffff) + 1);
        Util_TwosComplementInt(i, &iCompl);
        Assert::AreEqual(iTemp, iCompl);
    }

};
}
