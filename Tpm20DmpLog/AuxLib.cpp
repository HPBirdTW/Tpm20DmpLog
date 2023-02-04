#include "stdafx.h"
#include "Tpm20DmpLog.h"

HRESULT GetEventLogLoc(
    UINT8	**EventLogLocation,
	UINTN	*EventSize
)
{
    static BYTE*                pEventStart = NULL;
    UINT                        iLogSize = TBS_IN_OUT_BUF_SIZE_MAX;
    HRESULT                     hResult = 0;

    do
    {
        if (NULL == pEventStart)
        {
            pEventStart = new BYTE[iLogSize];
			memset(pEventStart, 0, iLogSize);
            if (NULL == pEventStart)
            {
                hResult = E_ABORT;
                break;
            }
        }

        hResult = GetTBSLog (pEventStart, &iLogSize);
        if (SUCCEEDED(hResult))
        {
            *EventLogLocation = pEventStart;
			*EventSize = iLogSize;
            return hResult;
        }
    } while (FALSE);

    return hResult;
}

HRESULT IsTCG_2_Event()
{
    TCG_PCR_EVENT						*pFirstEvent = NULL;
    TCG_PCClientSpecIDEventStructEx		*FisrHdrStruct = NULL;
    HRESULT								hResult = TBS_SUCCESS;
    UINT8								Signature[] = "Spec ID Event03";
	UINTN								EventTblSize;

    hResult = GetEventLogLoc(
        (UINT8**)&pFirstEvent, &EventTblSize);

    if (!SUCCEEDED(hResult))
    {
        return hResult;
    }

    if (EV_NO_ACTION != pFirstEvent->EventType || 0 != pFirstEvent->PCRIndex)
    {
        return TPM_VERSION_12;
    }

    FisrHdrStruct = (TCG_PCClientSpecIDEventStructEx*)&pFirstEvent->Event[0];

    if (memcmp(FisrHdrStruct, &Signature[0], sizeof(Signature)))
    {
        return TPM_VERSION_12;
    }

    return TPM_VERSION_20;
}

VOID sha1_vector(UINTN num_elem, CONST UINT8* addr[], CONST UINTN* len, UINT8* mac)
{
	SHA_CTX     ctx;
	UINTN       i;

	SHA1_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		SHA1_Update(&ctx, addr[i], len[i]);
	SHA1_Final(mac, &ctx);

	SetMem(&ctx, sizeof(ctx), 0);
}

VOID sha256_vector(
	UINTN           num_elem,
	CONST UINT8* addr[],
	CONST UINTN* len,
	UINT8* mac)
{
	SHA256_CTX  ctx;
	UINTN       i;

	SHA256_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		SHA256_Update(&ctx, addr[i], len[i]);
	SHA256_Final(mac, &ctx);

	SetMem(&ctx, sizeof(ctx), 0);
}

VOID sha384_vector(
	UINTN           num_elem,
	CONST UINT8* addr[],
	CONST UINTN* len,
	UINT8* mac)
{
	SHA512_CTX  ctx;
	UINTN       i;

	SHA384_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		SHA384_Update(&ctx, addr[i], len[i]);
	SHA384_Final(mac, &ctx);

	SetMem(&ctx, sizeof(ctx), 0);
}

VOID sha512_vector(
	UINTN           num_elem,
	CONST UINT8* addr[],
	CONST UINTN* len,
	UINT8* mac)
{
	SHA512_CTX  ctx;
	UINTN       i;

	SHA512_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		SHA512_Update(&ctx, addr[i], len[i]);
	SHA512_Final(mac, &ctx);

	SetMem(&ctx, sizeof(ctx), 0);
}

VOID sm3_vector(
	UINTN           num_elem,
	CONST UINT8* addr[],
	CONST UINTN* len,
	UINT8* mac)
{
	sm3_ctx_t       ctx;
	UINTN           i;

	sm3_init(&ctx);
	for (i = 0; i < num_elem; i++)
		sm3_update(&ctx, addr[i], len[i]);
	sm3_final(&ctx, mac);

	SetMem(&ctx, sizeof(ctx), 0);
}
