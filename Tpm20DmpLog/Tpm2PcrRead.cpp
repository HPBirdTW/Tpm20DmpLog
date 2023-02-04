#include "stdafx.h"
#include "Tpm20DmpLog.h"

#pragma pack(1)
typedef struct
{
	TPM2_COMMAND_HEADER Header;
	TPML_PCR_SELECTION  pcrSelection;
}TPM2_PCR_Read;

typedef struct
{
	TPM2_RESPONSE_HEADER    ResHead;
	UINT32                  pcrUpdateCounter;
	TPML_PCR_SELECTION      pcrSelectionOut;
	//    TPML_DIGEST             pcrValues;
}TPM2_PCR_Read_Res;

#pragma pack()

EFI_STATUS Tpm2ShaAlgoIdPCRRead(
	IN UINT16           AlgorithmId,
	IN TPM_PCRINDEX     PCRIndex,
	OUT UINT8*          Digest)
{
	EFI_STATUS              Status = TBS_SUCCESS;
	TPM2_PCR_Read           Cmd;
	UINTN                   unIdx;
	UINT32                  RetBufSize = 0x200;
	UINT8                   Res[0x200];
	TPM2_PCR_Read_Res       *pResCmd;
	TPML_DIGEST*            pRetDigest;

	SetMem(&Cmd, sizeof(Cmd), 0);

	Cmd.Header.tag = (TPM_ST)SwapBytes16(TPM_ST_NO_SESSIONS);
	Cmd.Header.commandCode = (TPM_CC)SwapBytes32(TPM_CC_PCR_Read);

	Cmd.pcrSelection.count = SwapBytes32(0x00000001);
	//    Cmd.pcrSelection.pcrSelections[0].hash = SwapBytes16(TPM_ALG_SHA1);    // SHA-1
	Cmd.pcrSelection.pcrSelections[0].hash = SwapBytes16(AlgorithmId);
	Cmd.pcrSelection.pcrSelections[0].sizeofSelect = (UINT8)PCR_SELECT_MIN;      // PCR 0~24 
	// Assign PCR Index.
	unIdx = PCRIndex / 8;
	Cmd.pcrSelection.pcrSelections[0].pcrSelect[unIdx] = (UINT8)1 << (PCRIndex % 8);

	Cmd.Header.paramSize =
		sizeof(Cmd.Header) +
		sizeof(Cmd.pcrSelection.count) +
		sizeof(Cmd.pcrSelection.pcrSelections[0]);

	Cmd.Header.paramSize = SwapBytes32(Cmd.Header.paramSize);

	Status = TpmSubmitCommand(
		SwapBytes32(Cmd.Header.paramSize),
		(UINT8*)&Cmd,
		&RetBufSize,
		Res
		);
	if (!SUCCEEDED(Status)) {
		//       TRACE((-1,"Tpm2SubmitCommand() Failed: [%r]\n", Status));
		return Status;
	}

	pResCmd = (TPM2_PCR_Read_Res*)Res;

	if (pResCmd->ResHead.responseCode)
	{
		//        TRACE((-1,"Tpm2PCRRead(...): ErrorCode[%x]\n", TPM_H2NL(pResCmd->ResHead.responseCode) ));
		return TPM_E_PCP_NOT_SUPPORTED;
	}

	// Here, need to extra check the pcr have also been selector.
	// 1. The pcrSelection count must be 1
	if (1 != TPM_H2NL( pResCmd->pcrSelectionOut.count ) )
	{
		return TPM_E_PCP_INVALID_PARAMETER;
	}
	// 2. must be the same algorithm
	if ( AlgorithmId != TPM_H2NS(pResCmd->pcrSelectionOut.pcrSelections[0].hash))
	{
		return TPM_E_PCP_INVALID_PARAMETER;
	}
	// 3. must match the same PcrIndex
	unIdx = PCRIndex / 8;
	if ((UINT8)1 << (PCRIndex % 8) != pResCmd->pcrSelectionOut.pcrSelections[0].pcrSelect[unIdx])
	{
		return TPM_E_PCP_INVALID_PARAMETER;
	}

	// Presp
	unIdx =
		// TPM2_RESPONSE_HEADER
		sizeof(pResCmd->ResHead)
		// UINT32
		+ sizeof(pResCmd->pcrUpdateCounter)
		// UINT32
		+ sizeof(pResCmd->pcrSelectionOut.count);

	unIdx +=
		// TPML_PCR_SELECTION->count * sizeof(TPMS_PCR_SELECTION)
		SwapBytes32(pResCmd->pcrSelectionOut.count) * sizeof(pResCmd->pcrSelectionOut.pcrSelections[0]);

	pRetDigest = (TPML_DIGEST*)&Res[unIdx];

	CopyMem(Digest, pRetDigest->digests[0].buffer, (UINTN)SwapBytes16(pRetDigest->digests[0].size));

	return Status;
}

EFI_STATUS Tpm2Sha1PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8           *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA1,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sha256PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA256,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sha384PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA384,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sha512PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SHA512,
                                        PCRIndex,
                                        Digest
                                        );
}

EFI_STATUS Tpm2Sm3_256PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest )
{
    return Tpm2ShaAlgoIdPCRRead(
                                        TPM_ALG_SM3_256,
                                        PCRIndex,
                                        Digest
                                        );
}

