// Tpm20DmpLog.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Tpm20DmpLog.h"

UINTN               g_EventStartAddr = 0;
UINTN               g_EventEndAddr = 0;

TBS_RESULT DmpTpmEventLog()
{
    HRESULT						hResult = 0;
    UINT						iLogSize = TBS_IN_OUT_BUF_SIZE_MAX;
    BYTE*						pEventStart = new BYTE[iLogSize];

    printf("Enter DmpTpmEventLog(...)\n");

    hResult = GetTBSLog(pEventStart, &iLogSize);

    if (SUCCEEDED(hResult))
        SPrintBufMixChar(iLogSize, pEventStart);

    printf("\n");

    delete pEventStart;

    return hResult;
}

int _tmain(int argc, _TCHAR* argv[])
{
    UINT32              TpmVersion;
    HRESULT             Result;
    EFI_STATUS          Status;

    printf("\nCreate by HPBirdChen, Ver: 1.1\n\n");

    Result = GetTpmDeviceType(&TpmVersion);
    if (!SUCCEEDED(Result) )
    {
        printf("\nDid not Detect TPM Device\n");
    }

	if (TPM_VERSION_12 == TpmVersion)
	{
        Tpm12Sha1DmpLog();
        Status = CalcSMLTpm12PCR();
	}

	if (TPM_VERSION_20 == TpmVersion)
	{
        if (TPM_VERSION_12 == IsTCG_2_Event())
        {
            Status = Tpm20Sha1DmpLog();
            Status = CalcSMLTpm20PCR_Tcg_1_2();
        }

        if (TPM_VERSION_20 == IsTCG_2_Event())
        {
            ShowSMLTpm20HashPCR();
        }

	}


	return 0;
}

