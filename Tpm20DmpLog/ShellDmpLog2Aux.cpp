/*
 * Copyright (C) 2019 HPBirdChen (hpbirdtw@gmail.com)
 * All rights reserved.
 * The License file locate on:
 * https://github.com/HPBirdTW/ShellTpmDmpLog/license.txt
 * */

#include "stdafx.h"
#include "Tpm20DmpLog.h"

wchar_t      u16StrBuf[0x400];

EFI_STATUS SPrintf(CHAR16* Format, ... )
{
    va_list     Marker;
 
    va_start(Marker, Format);

    vswprintf(u16StrBuf, sizeof(u16StrBuf) / sizeof(u16StrBuf[0]), Format, Marker);

    printf("%ls", u16StrBuf);

    return EFI_SUCCESS;
}

VOID SPrintBufMixChar(
    UINTN   unBufSize,
    UINT8*  _buf
)
{
    UINTN           unIdx;
    UINT8           LineBuf[0x10];
    UINT8           charLineBuf[0x11];
    UINTN           Remainder;

    SPrintf( L"\n\r");
    SetMem(&charLineBuf[0], sizeof(charLineBuf), 0);

    for( unIdx = 0; unIdx<unBufSize; ++unIdx )
    {
        LineBuf[ unIdx%0x10 ] = _buf[unIdx];

        if( _buf[unIdx] > 0x1F && _buf[unIdx] < 0x7F )
            charLineBuf[ unIdx%0x10 ] = _buf[unIdx];
        else
            charLineBuf[ unIdx%0x10 ] = '.';

        if( 0x0F == unIdx % 0x10 )
        {
            SPrintf(L" ");
            for( Remainder=0; Remainder < 0x10; ++Remainder )
            {
                SPrintf(L" %02x", (UINTN)LineBuf[Remainder] );
            }
            SPrintf(L" | ",&charLineBuf[0] );
            for( Remainder=0; Remainder < 0x10; ++Remainder )
            {
                SPrintf(L"%c", (UINTN)charLineBuf[Remainder] );
            }
            SPrintf(L"\n\r");
            SetMem(&charLineBuf[0], sizeof(charLineBuf), 0);
        }
    }

    Remainder = unIdx % 0x10;

    if( Remainder )
    {
        SPrintf(L" ");
        for( unIdx=0; unIdx<Remainder; ++unIdx)
        {
            SPrintf(L" %02x", (UINTN)LineBuf[unIdx] );
        }
        for( ; unIdx%0x10; ++unIdx )
        {
            SPrintf(L"   ");
        }
        SPrintf(L" | ",&charLineBuf[0] );
        for( unIdx=0; unIdx<Remainder; ++unIdx)
        {
            SPrintf(L"%c", (UINTN)charLineBuf[unIdx] );
        }
        SPrintf(L"\n\r");
    }
}

VOID SPrintBuf(
    UINTN   unBufSize,
    UINT8*  _buf
)
{
    UINTN           unIdx;
    EFI_STATUS      Status = EFI_SUCCESS;

    for( unIdx = 0; unIdx<unBufSize; ++unIdx )
    {
        if( unIdx % 0x10 == 0 )
        {
            SPrintf( L"\n\r ");
        }

        SPrintf( L" %02x", _buf[unIdx]);
    }

    SPrintf(L"\n\r");
}

EFI_STATUS TCG_PCR_EVENT_PrintOneEvent(TCG_PCR_EVENT* pStart, TCG_PCR_EVENT** pNext)
{
    UINT8*  _pStart = (UINT8*)pStart;
//    UINTN   unIdx;

    if( ( !pStart->EventType && !pStart->EventSize) )
        return -1;

//    SPrintf( L"Event Addr: [%08x]\n\r", (UINTN)pStart );

    *pNext = (TCG_PCR_EVENT*)(_pStart + STRUCT_FIELD_OFFSET( TCG_PCR_EVENT, Event ) + pStart->EventSize );

    SPrintf( L"PCRIndex  : [%08x]\n\r", (UINTN)pStart->PCRIndex );

    SPrintf( L"EventType : [%08x]\n\r", (UINTN)pStart->EventType );

    SPrintf( L"Digest:" );

    _pStart = (UINT8*)pStart;
    _pStart += STRUCT_FIELD_OFFSET( TCG_PCR_EVENT, Digest );

    SPrintBuf( sizeof(pStart->Digest), _pStart);

    SPrintf( L"EventData: Size[%04x]", (UINTN)pStart->EventSize );

    _pStart = (UINT8*)pStart;
    _pStart += STRUCT_FIELD_OFFSET( TCG_PCR_EVENT, Event );
    SPrintBufMixChar(pStart->EventSize, _pStart);
    SPrintf(L"\n\r");

    if( (UINTN)pStart + (UINTN)pStart->EventSize > g_EventEndAddr )
            return -1;

    return EFI_SUCCESS;
}


EFI_STATUS Sha1HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    CONST UINT8*    HashVectAddr[1];
    UINTN           HashVectAddrLen[1];

    HashVectAddr[0] = HashData;
    HashVectAddrLen[0] = HashDataLen;

    sha1_vector( 1, HashVectAddr, HashVectAddrLen, Digest );

    return Status;
}

EFI_STATUS Sha256HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    CONST UINT8*    HashVectAddr[1];
    UINTN           HashVectAddrLen[1];

    HashVectAddr[0] = HashData;
    HashVectAddrLen[0] = HashDataLen;

    sha256_vector( 1, HashVectAddr, HashVectAddrLen, Digest );

    return Status;
}

EFI_STATUS Sha384HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    CONST UINT8*    HashVectAddr[1];
    UINTN           HashVectAddrLen[1];

    HashVectAddr[0] = HashData;
    HashVectAddrLen[0] = HashDataLen;

    sha384_vector( 1, HashVectAddr, HashVectAddrLen, Digest );

    return Status;
}

EFI_STATUS Sha512HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    CONST UINT8*    HashVectAddr[1];
    UINTN           HashVectAddrLen[1];

    HashVectAddr[0] = HashData;
    HashVectAddrLen[0] = HashDataLen;

    sha512_vector( 1, HashVectAddr, HashVectAddrLen, Digest );

    return Status;
}

EFI_STATUS Sm3HashData(
    UINT8               *HashData,
    UINTN               HashDataLen,
    UINT8               *Digest
)
{
    EFI_STATUS      Status = EFI_SUCCESS;
    CONST UINT8*    HashVectAddr[1];
    UINTN           HashVectAddrLen[1];

    HashVectAddr[0] = HashData;
    HashVectAddrLen[0] = HashDataLen;

    sm3_vector( 1, HashVectAddr, HashVectAddrLen, Digest );

    return Status;
}
