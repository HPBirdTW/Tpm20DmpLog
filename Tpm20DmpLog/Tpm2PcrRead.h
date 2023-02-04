#include "Tpm20.h"
#ifndef _TPM2_PCR_READ_H
#define _TPM2_PCR_READ_H
// ---

EFI_STATUS Tpm2ShaAlgoIdPCRRead(
    IN UINT16           AlgorithmId,
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8*          Digest );

EFI_STATUS Tpm2Sha1PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8*          Digest );

EFI_STATUS Tpm2Sha256PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8           *Digest );

EFI_STATUS Tpm2Sha384PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest );

EFI_STATUS Tpm2Sha512PCRRead(
    IN TPM_PCRINDEX PCRIndex,
    OUT UINT8       *Digest );

EFI_STATUS Tpm2Sm3_256PCRRead(
    IN TPM_PCRINDEX     PCRIndex,
    OUT UINT8           *Digest );


// ---
#endif