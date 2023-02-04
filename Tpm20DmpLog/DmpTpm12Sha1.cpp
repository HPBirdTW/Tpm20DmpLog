#include "stdafx.h"
#include "Tpm20DmpLog.h"

EFI_STATUS TCG_PCR_EVENT_PrintOneEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

VOID Tpm12Sha1DmpLog(VOID)
{
	EFI_STATUS                          Status = EFI_SUCCESS;
	UINTN								EventStartAddr = 0;
	UINTN								EventEndAddr;
	UINTN								EventTblSize;
	TCG_PCR_EVENT*                      pNext = NULL;
	//    BOOLEAN                             bLogTruncated = FALSE;
	HRESULT								hResult = TBS_SUCCESS;


	//    TRACE((-1,"Enter Tpm20Sha1DmpLog(...)\n"));

	hResult = GetEventLogLoc(
		(UINT8**)&EventStartAddr, &EventTblSize);

	if (!SUCCEEDED(hResult))
	{
		return;
	}
	EventEndAddr = EventStartAddr + EventTblSize;
	g_EventStartAddr = (UINTN)EventStartAddr;
	g_EventEndAddr = (UINTN)EventEndAddr;

	SPrintf(L"Tpm12 DmpLog Event (...)\n\r");

	pNext = (TCG_PCR_EVENT*)EventStartAddr;
	do {
		if (0 == (UINTN)EventEndAddr)
		{
			SPrintf(L"Get Empty Event log\n\r");
			break;
		}
		if ((UINTN)pNext >= (UINTN)EventEndAddr)
		{
//			TCG_PCR_EVENT_PrintOneEvent(pNext, &pNext);
			SPrintf(L"End of the Event Log\n\r");
			break;
		}
	} while (EFI_SUCCESS == TCG_PCR_EVENT_PrintOneEvent(pNext, &pNext));

}

EFI_STATUS GetTpm12NextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

EFI_STATUS CalcSMLTpm12PCR(VOID)
{
	UINTN					EventStartAddr = 0;
   	UINTN    				EventEndAddr = 0;
	TCG_PCR_EVENT*          pNext = NULL;
	EFI_STATUS              Status;
	UINT8                   EvaDigest[2][SHA1_DIGEST_SIZE];
	UINT8                   HashVal[SHA1_DIGEST_SIZE];
	UINT8                   pcrValue[SHA1_DIGEST_SIZE];
	UINT32                  unPCRIdx = 0;
	EFI_STATUS Tpm12PCRRead(UINT32, UINT8*);

	HRESULT					hResult = TBS_SUCCESS;
	UINTN					EventTblSize;

	hResult = GetEventLogLoc(
		(UINT8**)&EventStartAddr, &EventTblSize);

	if (!SUCCEEDED(hResult))
	{
		return MAX_BIT;
	}
	EventEndAddr = EventStartAddr + EventTblSize;
	g_EventStartAddr = (UINTN)EventStartAddr;
	g_EventEndAddr = (UINTN)EventEndAddr;

	do
	{
		SPrintf(L"Start Tpm12 SML Calc Event(...)\n\r");
__RepCheck:
		pNext = (TCG_PCR_EVENT*)EventStartAddr;
		memset(EvaDigest, 0, sizeof(EvaDigest));
		memset(HashVal, 0, sizeof(HashVal));

		do {
			if (pNext->PCRIndex == unPCRIdx && pNext->EventType != 0x03)
			{
				CopyMem(&EvaDigest[1], &(pNext->Digest), SHA1_DIGEST_SIZE);
				Sha1HashData((UINT8*)(UINTN)&EvaDigest, sizeof(EvaDigest), &HashVal[0]);
				CopyMem(&EvaDigest[0], &HashVal, SHA1_DIGEST_SIZE);
			}
			Status = GetTpm12NextSMLEvent(pNext, &pNext);
		} while (EFI_SUCCESS == Status);

		SPrintf(L"\n\rEVA_VALUE[%02x]", (UINTN)unPCRIdx);
		SPrintBuf(SHA1_DIGEST_SIZE, &HashVal[0]);

		Tpm12PCRRead(unPCRIdx, &pcrValue[0]);
		SPrintf(L"PCR_VALUE[%02x]", (UINTN)unPCRIdx);
		SPrintBuf(SHA1_DIGEST_SIZE, &pcrValue[0]);

		if (++unPCRIdx <= 0x0F)
			goto __RepCheck;

		SPrintf(L"\n\rEnd Tpm12 SML Calc Event(...)\n\r");
	} while (FALSE);

	return Status;
}

EFI_STATUS GetTpm12NextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext)
{
	UINT8* _pStart = (UINT8*)pStart;
	UINTN           unIdx = 0;

	*pNext = (TCG_PCR_EVENT*)(_pStart + STRUCT_FIELD_OFFSET(TCG_PCR_EVENT, Event) + pStart->EventSize);

	if ((UINTN)(*pNext) > g_EventEndAddr)
		return -1;

	if (!(*pNext)->EventType && !(*pNext)->EventSize)
		return -1;

	return EFI_SUCCESS;
}

#pragma pack (push, 1)
typedef struct _Tpm12_PcrRead_Cmd {
	UINT16                tag;
	UINT32                paramSize;
	UINT32                ordinal;
	UINT32                pcrIndex;
} Tpm12_PcrRead_Cmd;

typedef struct _Tpm12_PcrRead_Ret {
	UINT16                tag;
	UINT32                paramSize;
	UINT32                returnCode;
	UINT8                 outDigest[20];
} Tpm12_PcrRead_Ret;
#pragma pack (pop)

EFI_STATUS Tpm12PCRRead(
	IN  UINT32      PCRIndex,
	OUT UINT8* Digest)
{
	Tpm12_PcrRead_Cmd   Cmd;
	Tpm12_PcrRead_Ret   Ret;
	EFI_STATUS          Status;
	UINT32              u32RetSize;

	Cmd.tag = SwapBytes16(TPM_TAG_RQU_COMMAND);
	Cmd.paramSize = SwapBytes32(sizeof(Cmd));

	Cmd.ordinal = SwapBytes32(TPM_ORD_PcrRead);
	Cmd.pcrIndex = SwapBytes32(PCRIndex);

	u32RetSize = sizeof(Ret);
	Status = TpmSubmitCommand(
		sizeof(Cmd),
		(UINT8*)&Cmd,
		&u32RetSize,
		(UINT8*)&Ret
	);
	if (SUCCEEDED(Status))
	{
		if (Ret.returnCode)
		{
			Status = EFI_NOT_READY;
		}
		else
		{
			CopyMem(Digest, Ret.outDigest, sizeof(Ret.outDigest));
		}
	}

	return Status;
}
