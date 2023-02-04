
#include "stdafx.h"
#include "Tpm20DmpLog.h"

#include <tbs.h>
#pragma comment(lib, "Tbs.lib")

TBS_RESULT TpmSubmitCommand(
    UINT		uCmdSize,
    UINT8*		pInCmdBuf,
    UINT*		uResBufSize,
    UINT8*		pOutResBuf
	)
{
    TBS_HCONTEXT		hTbsContext = NULL;
    TBS_CONTEXT_PARAMS2	tbsContextParams;
    HRESULT				hResult;
    TPM_RESPONSE_HEADER *retHeader;
    UINT32				u32TmpVal;
    TPM_COMMAND_HEADER  *cmdHeader;

    do
    {
        memset(&tbsContextParams, 0, sizeof(tbsContextParams));
        tbsContextParams.version = TPM_VERSION_20;
        tbsContextParams.requestRaw = 1;
        tbsContextParams.includeTpm12 = 1;
        tbsContextParams.includeTpm20 = 1;
        hResult = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&tbsContextParams, &hTbsContext);
        if (SUCCEEDED(hResult))
        {
            break;
        }

        memset(&tbsContextParams, 0, sizeof(tbsContextParams));
        tbsContextParams.version = TPM_VERSION_12;
        hResult = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&tbsContextParams, &hTbsContext);
        if (SUCCEEDED(hResult))
        {
            break;
        }
    } while (FALSE);

    if (SUCCEEDED(hResult))
    {

        cmdHeader = (TPM_COMMAND_HEADER *)pInCmdBuf;
        u32TmpVal = SwapBytes32(cmdHeader->paramSize);

        hResult = Tbsip_Submit_Command(hTbsContext,
            TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_SYSTEM,
            pInCmdBuf, uCmdSize,
            pOutResBuf, uResBufSize);

        if (SUCCEEDED(hResult))
        {
            retHeader = (TPM_RESPONSE_HEADER*)pOutResBuf;
            if (retHeader->responseCode)
            {
                //              printf("[%d]: Tpm Response Err", __LINE__);
                //              PrintBufMixChar(SwapBytes32(retHeader->paramSize), pOutResBuf);
            }

            u32TmpVal = SwapBytes32(retHeader->paramSize);
            *uResBufSize = u32TmpVal;
        }
        else
        {
            printf("[%d]: Err. Tbsip_Submit_Command[%x]\n", __LINE__, hResult);
        }
    }

    //Done:
    if (NULL != hTbsContext)
    {
        Tbsip_Context_Close(hTbsContext);
        hTbsContext = NULL;
    }

    return hResult;
}

HRESULT GetTpmDeviceType(
    UINT32  *TpmVersion
)
{
    TBS_CONTEXT_PARAMS2			contextParams;
    TBS_HCONTEXT				hContext;
    HRESULT						hResult = 0;
    BOOLEAN                     bTpm12 = FALSE;
    //    TPM_DEVICE_INFO				DeviceInfo;

    do
    {
        bTpm12 = FALSE;

        memset(&contextParams, 0, sizeof(contextParams));
        contextParams.version = TPM_VERSION_20;
        contextParams.requestRaw = 1;
        contextParams.includeTpm12 = 1;
        contextParams.includeTpm20 = 0;

        hContext = 0;
        hResult = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&contextParams, &hContext);
        if (SUCCEEDED(hResult))
        {
            bTpm12 = TRUE;
            break;
        }

        memset(&contextParams, 0, sizeof(contextParams));
        contextParams.version = TPM_VERSION_20;
        contextParams.requestRaw = 1;
        contextParams.includeTpm12 = 0;
        contextParams.includeTpm20 = 1;

        hContext = 0;
        hResult = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&contextParams, &hContext);
        if (SUCCEEDED(hResult))
        {
            bTpm12 = FALSE;
            break;
        }

        memset(&contextParams, 0, sizeof(contextParams));
        contextParams.version = TBS_CONTEXT_VERSION_ONE;
        hContext = 0;
        hResult = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&contextParams, &hContext);
        if (SUCCEEDED(hResult))
        {
            bTpm12 = TRUE;
            break;
        }
    } while (FALSE);

    if (!SUCCEEDED(hResult))
    {
        printf("[%d]: Did not get the TPM Device Handle - 0x%x\n", __LINE__, hResult);
        return hResult;
    }

    do
    {
#if 0
        if (bWin8)
        {
            DeviceInfo.structVersion = 1;
            hResult = Tbsi_GetDeviceInfo(sizeof(DeviceInfo), &DeviceInfo);
            if (!SUCCEEDED(hResult))
            {
                printf("[%d]: Did not get the TPM Device Info - 0x%x\n", __LINE__, hResult);
                break;
            }
        }
        else
        {
            DeviceInfo.tpmVersion = TPM_VERSION_12;
        }

        hResult = Tbsip_Context_Close(hContext);
        if (!SUCCEEDED(hResult))
        {
            break;
        }

        *TpmVersion = DeviceInfo.tpmVersion; // TPM_VERSION_12 or TPM_VERSION_20
#endif
        *TpmVersion = bTpm12 ? TPM_VERSION_12 : TPM_VERSION_20; // TPM_VERSION_12 or TPM_VERSION_20
    } while (FALSE);

    return hResult;
}

TBS_RESULT GetTBSLog(UINT8* pLogBuf, UINT *pSize)
{
	TBS_RESULT			result;
	TBS_HCONTEXT		hContext = NULL;
	TBS_CONTEXT_PARAMS2 contextParams;
	UINT32				iLogSize = TBS_IN_OUT_BUF_SIZE_MAX;
	BYTE				*pLogBuffer = NULL;

    do
    {
        memset(&contextParams, 0, sizeof(contextParams));
        contextParams.version = TPM_VERSION_20;
        contextParams.requestRaw = 1;
        contextParams.includeTpm12 = 1;
        contextParams.includeTpm20 = 1;
        result = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&contextParams, &hContext);
        if (SUCCEEDED(result))
        {
            break;
        }

        memset(&contextParams, 0, sizeof(contextParams));
        contextParams.version = TPM_VERSION_12;
        result = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&contextParams, &hContext);
        if (SUCCEEDED(result))
        {
            break;
        }
    } while (FALSE);

    do
    {
        if (!SUCCEEDED(result))
        {
            break;
        }

        pLogBuffer = new BYTE[iLogSize];
        if (NULL == pLogBuffer)
        {
            result = E_ABORT;
            break;
        }

        result = Tbsi_Get_TCG_Log(hContext, pLogBuffer, &iLogSize);
        if (result == TBS_SUCCESS)
        {
            //			PrintBuf(iLogSize, pLogBuffer);
            if (*pSize < iLogSize || NULL == pLogBuf)
            {
                printf("[%d]: Input Buffer too small or pLogBuf[NULL].\n", __LINE__);
                result = E_ABORT;
                break;
            }

            *pSize = iLogSize;
            memcpy(pLogBuf, pLogBuffer, iLogSize);
        }

    } while (FALSE);

	if (pLogBuffer)
	{
		delete pLogBuffer;
		pLogBuffer = NULL;
	}

	if (NULL != hContext)
	{
		Tbsip_Context_Close(hContext);
		hContext = NULL;
	}
		
	if (TBS_SUCCESS != result)
	{
		printf("[%d]: Error GetTBSLog - %x .\n", __LINE__, result);
	}

	return result;
}