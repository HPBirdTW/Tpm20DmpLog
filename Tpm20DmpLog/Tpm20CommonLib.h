#ifndef __TPM20_COMMON_LIB_H
#define __TPM20_COMMON_LIB_H
// ---

#include <tbs.h>

#define TPM_H2NS( x ) \
    (UINT16)( (((UINT16)(x) << 8) | ((UINT16)(x) >> 8)) )
#define TPM_H2NL( x ) \
    (UINT32)((((UINT32)(x)) >> 24)    \
             | (((x) >> 8) & 0xff00)  \
             | ((x) << 24)            \
             | (((x) & 0xff00) << 8))

#define SwapBytes16(x)  TPM_H2NS(x)
#define SwapBytes32(x)  TPM_H2NL(x)

#pragma pack (1)

typedef struct {
    UINT16 tag;
    UINT32 paramSize;
    UINT32 ordinal;
}TPM_COMMAND_HEADER;

typedef struct {
	UINT16 tag;
	UINT32 paramSize;
	UINT32 responseCode;
} TPM_RESPONSE_HEADER;

#pragma pack ()

TBS_RESULT TpmSubmitCommand(
	UINT		uCmdSize,
	UINT8*		pInCmdBuf,
	UINT*		uResBuf,
	UINT8*		pOutResBuf
);

TBS_RESULT GetTBSLog(
	UINT8* pLogBuf,
	UINT *pSize
);


// ---
#endif