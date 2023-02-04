#ifndef __TPM20_DMPLOG_H
#define __TPM20_DMPLOG_H
// --

#ifndef UINTN
#define UINTN		size_t
#endif

#ifndef EFI_STATUS
#define EFI_STATUS	size_t
#endif

#ifndef CHAR16
#define CHAR16		wchar_t
#endif

VOID SPrintBufMixChar(
	UINTN   unBufSize,
	UINT8* _buf
);

EFI_STATUS SPrintf(CHAR16* _str, ...);

VOID SPrintBuf(
	UINTN   unBufSize,
	UINT8* _buf
);

#define STRUCT_FIELD_OFFSET( type, field )  \
    ((UINTN)&(((type*)0)->field))


#pragma pack (1)

	typedef struct _TCG_PCR_EVENT {
		UINT32            PCRIndex;  // PCRIndex event extended to
		UINT32            EventType; // TCG EFI event type
		UINT8             Digest[20];    // Value extended into PCRIndex
		UINT32            EventSize; // Size of the event data
		UINT8             Event[1];  // The event data
	} TCG_PCR_EVENT;

	typedef struct
	{
		UINT8  Signature[16];
		UINT32 PlatformClass;
		UINT8  SpecVersionMinor;
		UINT8  SpecVersionMajor;
		UINT8  SpecErrata;
		UINT8  uintnSize;
		UINT32 numberOfAlgorithms;
//		TCG_EFISpecIdEventAlgorithmSize digestSizes[5];
//		UINT8  VendorInfoSize;
	} TCG_PCClientSpecIDEventStructEx;

	typedef struct 
	{
		UINT8   Signature[16];
		UINT8   StartupLocality;
	} TCG_EFI_STARTUP_LOCALITY_EVENT;

#pragma pack ()

extern UINTN               g_EventStartAddr;
extern UINTN               g_EventEndAddr;

#ifndef EFI_TCG2_EVENT_LOG_FORMAT_TCG_2
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_2     0x00000002
#endif

#ifndef EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2   0x00000001
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA1
#define EFI_TCG2_BOOT_HASH_ALG_SHA1         0x00000001
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA256
#define EFI_TCG2_BOOT_HASH_ALG_SHA256       0x00000002
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA384
#define EFI_TCG2_BOOT_HASH_ALG_SHA384       0x00000004
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SHA512
#define EFI_TCG2_BOOT_HASH_ALG_SHA512       0x00000008
#endif

#ifndef EFI_TCG2_BOOT_HASH_ALG_SM3_256
#define EFI_TCG2_BOOT_HASH_ALG_SM3_256      0x00000010
#endif

#ifndef EFIAPI
#define EFIAPI
#endif


HRESULT GetEventLogLoc(
	UINT8** EventLogLocation,
	UINTN* EventSize
);

HRESULT IsTCG_2_Event();
HRESULT GetTpmDeviceType(
    UINT32  *TpmVersion
);

EFI_STATUS Sha1HashData(
	UINT8* HashData,
	UINTN               HashDataLen,
	UINT8* Digest
);

EFI_STATUS Sha256HashData(
	UINT8* HashData,
	UINTN               HashDataLen,
	UINT8* Digest
);

EFI_STATUS Sha384HashData(
	UINT8* HashData,
	UINTN               HashDataLen,
	UINT8* Digest
);

EFI_STATUS Sha512HashData(
	UINT8* HashData,
	UINTN               HashDataLen,
	UINT8* Digest
);

EFI_STATUS Sm3HashData(
	UINT8* HashData,
	UINTN               HashDataLen,
	UINT8* Digest
);

VOID sha1_vector(UINTN num_elem, CONST UINT8* addr[], CONST UINTN* len,
	UINT8* mac);

VOID sha256_vector(UINTN num_elem, CONST UINT8* addr[], CONST UINTN* len,
	UINT8* mac);

VOID sha384_vector(UINTN num_elem, CONST UINT8* addr[], CONST UINTN* len,
	UINT8* mac);

VOID sha512_vector(UINTN num_elem, CONST UINT8* addr[], CONST UINTN* len,
	UINT8* mac);

VOID sm3_vector(UINTN num_elem, CONST UINT8* addr[], CONST UINTN* len,
	UINT8* mac);

#define SetMem(dest, size, val) memset( dest, val, size)
#define CopyMem(dest, src, size) memcpy( dest, src, size)
#define CompareMem memcmp
#define EFI_SUCCESS TBS_SUCCESS
#define EV_NO_ACTION                3

#define MAX_BIT	(1 << (sizeof(EFI_STATUS)*8 -1))
#define EFI_ERROR(Status) ((Status) > 0)

#define EFI_NOT_READY			((-1)|MAX_BIT)
#define EFI_NOT_FOUND			((-1)|MAX_BIT)
#define EFI_INVALID_PARAMETER	((-1)|MAX_BIT)
#define EFI_DEVICE_ERROR		((-1)|MAX_BIT)
#define EFI_OUT_OF_RESOURCES	((-1)|MAX_BIT)

#ifndef DEBUG
#define DEBUG(arg)
#endif

#include "Tpm20CommonLib.h"
#include "Tpm2PcrRead.h"
#include "sha.h"
#include "SM3.h"
// --

EFI_STATUS Tpm20Sha1DmpLog(VOID);
EFI_STATUS CalcSMLTpm20PCR_Tcg_1_2(VOID);
VOID       Tpm12Sha1DmpLog(VOID);
EFI_STATUS CalcSMLTpm12PCR(VOID);
EFI_STATUS ShowSMLTpm20HashPCR(VOID);

#endif