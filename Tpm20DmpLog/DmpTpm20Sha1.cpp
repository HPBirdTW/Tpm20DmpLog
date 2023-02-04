#include "stdafx.h"
#include "Tpm20DmpLog.h"

EFI_STATUS TCG_PCR_EVENT_PrintOneEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);
EFI_STATUS GetNextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext);

struct
{
	UINT32  ManufactureId;
	CHAR16* str;
} CONST VenderID[] = {
		{   0x414d4400,     L"AMD(fTPM)" },
		{   0x41544d4c,     L"Atmel"     },
		{   0x4252434d,     L"Broadcom"  },
		{   0x49424d00,     L"IBM"       },
		{   0x49465800,     L"Infineon"  },
		{   0x494e5443,     L"Intel(fTPM)"   },
		{   0x4c454e00,     L"Lenovo"    },
		{   0x4e534d20,     L"National Semi" },
		{   0x4e545a00,     L"Nationz"   },
		{   0x4e544300,     L"Nuvoton Technology"    },
		{   0x51434f4d,     L"Qualcomm"  },
		{   0x534d5343,     L"SMSC"      },
		{   0x53544d20,     L"STMicroelectronics"    },
		{   0x534d534e,     L"Samsung"   },
		{   0x534e5300,     L"Sinosun"   },
		{   0x54584e00,     L"Texas Instruments" },
		{   0x57454300,     L"Winbond"   },
		{   0x524f4343,     L"Fuzhou Rockchip"   }
};

EFI_STATUS Tpm20Sha1DmpLog(VOID)
{
	EFI_STATUS                      Status = EFI_SUCCESS;
	TCG_PCR_EVENT*					pNext = NULL;
	UINTN                           unEventCount = 0;
	UINTN							EventStartAddr = 0;
	UINTN							EventEndAddr = 0;
	UINTN							EventTblSize = 0;
	HRESULT							hResult = TBS_SUCCESS;

	//    DEBUG((DEBUG_INFO,"Enter TCG_1_2(...)\n"));

	do
	{
		hResult = GetEventLogLoc(
			(UINT8**)&EventStartAddr, &EventTblSize);

		if (!SUCCEEDED(hResult))
		{
			break;
		}

		EventEndAddr = EventStartAddr + EventTblSize;

		g_EventStartAddr = (UINTN)EventStartAddr;
		g_EventEndAddr = (UINTN)EventEndAddr;

		SPrintf(L"\n\rDump Tpm20 TCG_1_2 Event(...)\n\r");

		pNext = (TCG_PCR_EVENT*)EventStartAddr;
		do {
			if (0 == (UINTN)EventEndAddr)
			{
				SPrintf(L"Get Empty Event log\n\r");
				break;
			}
			++unEventCount;
			if ((UINTN)pNext >= (UINTN)EventEndAddr)
			{
//				TCG_PCR_EVENT_PrintOneEvent(pNext, &pNext);
				SPrintf(L"End of the Event Log, Total Count [%d]\n\r", unEventCount);
				break;
			}
		} while (EFI_SUCCESS == TCG_PCR_EVENT_PrintOneEvent(pNext, &pNext));

	} while (FALSE);

	return Status;
}

EFI_STATUS ChkSha1StartupLocalityEvent(TCG_PCR_EVENT* pEvent, UINTN* Locality)
{
	EFI_STATUS                          Status;
	CONST UINT8                         StartLocality[] = "StartupLocality";

	do
	{
		Status = EFI_SUCCESS;
		if (pEvent->PCRIndex != 0x00)
		{
			Status = EFI_NOT_FOUND;
			break;
		}
		if (pEvent->EventType != 0x03)
		{
			Status = EFI_NOT_FOUND;
			break;
		}
		if (pEvent->EventSize != sizeof(TCG_EFI_STARTUP_LOCALITY_EVENT))
		{
			Status = EFI_NOT_FOUND;
			break;
		}
		if (0 != CompareMem(((TCG_EFI_STARTUP_LOCALITY_EVENT*)pEvent->Event)->Signature, StartLocality, sizeof(StartLocality)))
		{
			Status = EFI_NOT_FOUND;
			break;
		}

		*Locality = (UINTN)((TCG_EFI_STARTUP_LOCALITY_EVENT*)pEvent->Event)->StartupLocality;
	} while (0);

	return Status;
}

EFI_STATUS CalcSMLTpm20PCR_Tcg_1_2(VOID)
{
	UINTN					EventStartAddr = 0;
	UINTN					EventEndAddr = 0;
	TCG_PCR_EVENT*			pNext = NULL;
	HRESULT					hResult = TBS_SUCCESS;
	EFI_STATUS              Status;
	UINT8                   EvaDigest[2][SHA1_DIGEST_SIZE];
	UINT8                   HashVal[SHA1_DIGEST_SIZE];
	UINT8                   pcrValue[SHA1_DIGEST_SIZE];
	UINT8                   EmptyDigest[SHA1_DIGEST_SIZE];
	UINT32                  unPCRIdx = 0;
	UINTN                   unInitStartupLocality = 0;
	UINTN					EventTblSize = 0;

	//    DEBUG((DEBUG_INFO,"Enter CalcSMLTpm20PCR_Tcg_1_2(...)"));

	do
	{
		hResult = GetEventLogLoc(
			(UINT8**)&EventStartAddr, &EventTblSize);

		if (!SUCCEEDED(hResult))
		{
			break;
		}

		EventEndAddr = EventStartAddr + EventTblSize;

		if (0 == EventStartAddr || 0 == EventEndAddr)
		{
			Status = EFI_INVALID_PARAMETER;
			SPrintf(L"Invalid parameter of (EventLogLocation | EventLogLastEntry)\n\r");
			break;
		}

		g_EventStartAddr = (UINTN)EventStartAddr;
		g_EventEndAddr = (UINTN)EventEndAddr;

		SPrintf(L"\n\rStart Tpm20 TCG_1_2 Calc Event(...)");

		SetMem(EmptyDigest, sizeof(EmptyDigest), 0);

	__RepCheck:
		pNext = (TCG_PCR_EVENT*)EventStartAddr;
		SetMem(EvaDigest, sizeof(EvaDigest), 0);
		SetMem(HashVal, sizeof(HashVal), 0);

		do {
			Status = ChkSha1StartupLocalityEvent(pNext, &unInitStartupLocality);
			if ( !EFI_ERROR(Status) && 0 == unPCRIdx)
			{
				EvaDigest[0][SHA1_DIGEST_SIZE - 1] = (UINT8)unInitStartupLocality;
			}
			if (pNext->PCRIndex == unPCRIdx && pNext->EventType != 0x03)
			{
				CopyMem(&EvaDigest[1], &(pNext->Digest), SHA1_DIGEST_SIZE);
				Sha1HashData((UINT8*)(UINTN)&EvaDigest, sizeof(EvaDigest), &HashVal[0]);
				CopyMem(&EvaDigest[0], &HashVal, SHA1_DIGEST_SIZE);
			}
			Status = GetNextSMLEvent(pNext, &pNext);
		} while (EFI_SUCCESS == Status);

		SPrintf(L"\n\rEVA_VALUE[%02x]", (UINTN)unPCRIdx);
		SPrintBuf(SHA1_DIGEST_SIZE, &HashVal[0]);

		SetMem(&pcrValue[0], sizeof(pcrValue), 0);
		Status = Tpm2Sha1PCRRead(unPCRIdx, &pcrValue[0]);
		if (!EFI_ERROR(Status))
		{
			SPrintf(L"PCR_VALUE[%02x]", (UINTN)unPCRIdx);

			SPrintBuf(SHA1_DIGEST_SIZE, &pcrValue[0]);
		}
		else
		{
			SPrintf(L"\n\r Failed Tpm2Sha1PCRRead (...) - %r [0x%08x]\n\r", Status, (UINTN)Status);
		}

		if (++unPCRIdx <= 0x0F)
			goto __RepCheck;
	} while (FALSE);
	SPrintf(L"\n\rEnd Tpm20 TCG_1_2 Calc Event(...)\n\r");

	return Status;
}

EFI_STATUS GetNextSMLEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext)
{
	UINT8* _pStart = (UINT8*)pStart;
	UINTN           unIdx = 0;

	*pNext = (TCG_PCR_EVENT*)(_pStart + STRUCT_FIELD_OFFSET(TCG_PCR_EVENT, Event) + pStart->EventSize);

	if ((UINTN)(*pNext) > g_EventEndAddr)
		return EFI_NOT_FOUND;

	if (!(*pNext)->EventType && !(*pNext)->EventSize)
		return EFI_NOT_FOUND;

	return EFI_SUCCESS;
}
