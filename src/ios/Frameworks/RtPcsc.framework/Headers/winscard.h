/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

//  Copyright (c) 2013 Aktiv Co. All rights reserved.

#ifndef pcsc_ios_winscard_h
#define pcsc_ios_winscard_h

#include "wintypes.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef LONG SCARDCONTEXT;
typedef SCARDCONTEXT* LPSCARDCONTEXT;
typedef LONG SCARDHANDLE;
typedef SCARDHANDLE* LPSCARDHANDLE;

typedef struct
{
	LPCSTR szReader;
	LPVOID pvUserData;
	DWORD dwCurrentState;
	DWORD dwEventState;
	DWORD cbAtr;
	BYTE rgbAtr[36];
} SCARD_READERSTATE_A;
typedef SCARD_READERSTATE_A* LPSCARD_READERSTATE_A;
typedef const SCARD_READERSTATE_A* LPCSCARD_CREADERSTATE_A;

typedef struct
{
	LPCWSTR szReader;
	LPVOID pvUserData;
	DWORD dwCurrentState;
	DWORD dwEventState;
	DWORD cbAtr;
	BYTE rgbAtr[36];
} SCARD_READERSTATE_W;
typedef SCARD_READERSTATE_W* LPSCARD_READERSTATE_W;
typedef const SCARD_READERSTATE_W* LPCSCARD_READERSTATE_W;

typedef struct
{
	unsigned long dwProtocol;
	unsigned long cbPciLength;
} SCARD_IO_REQUEST;
typedef SCARD_IO_REQUEST* LPSCARD_IO_REQUEST;
typedef const SCARD_IO_REQUEST* LPCSCARD_IO_REQUEST;

extern const SCARD_IO_REQUEST* SCARD_PCI_T0;
extern const SCARD_IO_REQUEST* SCARD_PCI_T1;
extern const SCARD_IO_REQUEST* SCARD_PCI_RAW;

#ifdef _UNICODE
typedef SCARD_READERSTATE_W SCARD_READERSTATE;
#else
typedef SCARD_READERSTATE_A SCARD_READERSTATE;
#endif

typedef SCARD_READERSTATE* LPSCARD_READERSTATE;
typedef const SCARD_READERSTATE* LPCSCARD_READERSTATE;

LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext);

LONG SCardReleaseContext(SCARDCONTEXT hContext);

LONG SCardConnectA(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols,
                   LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);

LONG SCardConnectW(SCARDCONTEXT hContext, LPCWSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols,
                   LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);

LONG SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization,
                    LPDWORD pdwActiveProtocol);

LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition);

LONG SCardBeginTransaction(SCARDHANDLE hCard);

LONG SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition);

LONG SCardStatusA(SCARDHANDLE hCard, LPSTR mszReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState,
                  LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen);

LONG SCardStatusW(SCARDHANDLE hCard, LPWSTR mszReaderName, LPDWORD pcchReaderLen, LPDWORD pdwState,
                  LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen);

LONG SCardGetStatusChangeA(SCARDCONTEXT hContext, DWORD dwTimeout, LPSCARD_READERSTATE_A rgReaderStates,
                           DWORD cReaders);

LONG SCardGetStatusChangeW(SCARDCONTEXT hContext, DWORD dwTimeout, LPSCARD_READERSTATE_W rgReaderStates,
                           DWORD cReaders);

/// Not implemented
LONG SCardControl(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer,
                  DWORD cbRecvLength, LPDWORD lpBytesReturned);

LONG SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen);

/// Not implemented
LONG SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPCBYTE pbAttr, DWORD cbAttrLen);

LONG SCardTransmit(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci, LPCBYTE pbSendBuffer, DWORD cbSendLength,
                   LPSCARD_IO_REQUEST pioRecvPci, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);

LONG SCardListReadersA(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders);

LONG SCardListReadersW(SCARDCONTEXT hContext, LPCWSTR mszGroups, LPWSTR mszReaders, LPDWORD pcchReaders);

LONG SCardFreeMemory(SCARDCONTEXT hContext, LPCVOID pvMem);

/// Not implemented
LONG SCardListReaderGroups(SCARDCONTEXT hContext, LPSTR mszGroups, LPDWORD pcchGroups);

/// Not implemented
LONG SCardCancel(SCARDCONTEXT hContext);

LONG SCardIsValidContext(SCARDCONTEXT hContext);

#ifdef _UNICODE
#define SCardConnect SCardConnectW
#define SCardStatus SCardStatusW
#define SCardGetStatusChange SCardGetStatusChangeW
#define SCardListReaders SCardListReadersW
#else
#define SCardConnect SCardConnectA
#define SCardStatus SCardStatusA
#define SCardGetStatusChange SCardGetStatusChangeA
#define SCardListReaders SCardListReadersA
#endif

#define SCARD_S_SUCCESS ((LONG)0x00000000)
#define SCARD_F_INTERNAL_ERROR ((LONG)0x80100001)
#define SCARD_E_CANCELLED ((LONG)0x80100002)
#define SCARD_E_INVALID_HANDLE ((LONG)0x80100003)
#define SCARD_E_INVALID_PARAMETER ((LONG)0x80100004)
#define SCARD_E_INVALID_TARGET ((LONG)0x80100005)
#define SCARD_E_NO_MEMORY ((LONG)0x80100006)
#define SCARD_F_WAITED_TOO_LONG ((LONG)0x80100007)
#define SCARD_E_INSUFFICIENT_BUFFER ((LONG)0x80100008)
#define SCARD_E_UNKNOWN_READER ((LONG)0x80100009)
#define SCARD_E_TIMEOUT ((LONG)0x8010000A)
#define SCARD_E_SHARING_VIOLATION ((LONG)0x8010000B)
#define SCARD_E_NO_SMARTCARD ((LONG)0x8010000C)
#define SCARD_E_UNKNOWN_CARD ((LONG)0x8010000D)
#define SCARD_E_CANT_DISPOSE ((LONG)0x8010000E)
#define SCARD_E_PROTO_MISMATCH ((LONG)0x8010000F)
#define SCARD_E_NOT_READY ((LONG)0x80100010)
#define SCARD_E_INVALID_VALUE ((LONG)0x80100011)
#define SCARD_E_SYSTEM_CANCELLED ((LONG)0x80100012)
#define SCARD_F_COMM_ERROR ((LONG)0x80100013)
#define SCARD_F_UNKNOWN_ERROR ((LONG)0x80100014)
#define SCARD_E_INVALID_ATR ((LONG)0x80100015)
#define SCARD_E_NOT_TRANSACTED ((LONG)0x80100016)
#define SCARD_E_READER_UNAVAILABLE ((LONG)0x80100017)
#define SCARD_P_SHUTDOWN ((LONG)0x80100018)
#define SCARD_E_PCI_TOO_SMALL ((LONG)0x80100019)
#define SCARD_E_READER_UNSUPPORTED ((LONG)0x8010001A)
#define SCARD_E_DUPLICATE_READER ((LONG)0x8010001B)
#define SCARD_E_CARD_UNSUPPORTED ((LONG)0x8010001C)
#define SCARD_E_NO_SERVICE ((LONG)0x8010001D)
#define SCARD_E_SERVICE_STOPPED ((LONG)0x8010001E)
#define SCARD_E_UNEXPECTED ((LONG)0x8010001F)
#define SCARD_E_ICC_INSTALLATION ((LONG)0x80100020)
#define SCARD_E_ICC_CREATEORDER ((LONG)0x80100021)
#define SCARD_E_UNSUPPORTED_FEATURE ((LONG)0x80100022)
#define SCARD_E_DIR_NOT_FOUND ((LONG)0x80100023)
#define SCARD_E_FILE_NOT_FOUND ((LONG)0x80100024)
#define SCARD_E_NO_DIR ((LONG)0x80100025)
#define SCARD_E_NO_FILE ((LONG)0x80100026)
#define SCARD_E_NO_ACCESS ((LONG)0x80100027)
#define SCARD_E_WRITE_TOO_MANY ((LONG)0x80100028)
#define SCARD_E_BAD_SEEK ((LONG)0x80100029)
#define SCARD_E_INVALID_CHV ((LONG)0x8010002A)
#define SCARD_E_UNKNOWN_RES_MNG ((LONG)0x8010002B)
#define SCARD_E_NO_SUCH_CERTIFICATE ((LONG)0x8010002C)
#define SCARD_E_CERTIFICATE_UNAVAILABLE ((LONG)0x8010002D)
#define SCARD_E_NO_READERS_AVAILABLE ((LONG)0x8010002E)
#define SCARD_E_COMM_DATA_LOST ((LONG)0x8010002F)
#define SCARD_E_NO_KEY_CONTAINER ((LONG)0x80100030)
#define SCARD_E_SERVER_TOO_BUSY ((LONG)0x80100031)
#define SCARD_E_PIN_CACHE_EXPIRED ((LONG)0x80100032)
#define SCARD_E_NO_PIN_CACHE ((LONG)0x80100033)
#define SCARD_E_READ_ONLY_CARD ((LONG)0x80100034)
#define SCARD_W_UNSUPPORTED_CARD ((LONG)0x80100065)
#define SCARD_W_UNRESPONSIVE_CARD ((LONG)0x80100066)
#define SCARD_W_UNPOWERED_CARD ((LONG)0x80100067)
#define SCARD_W_RESET_CARD ((LONG)0x80100068)
#define SCARD_W_REMOVED_CARD ((LONG)0x80100069)
#define SCARD_W_SECURITY_VIOLATION ((LONG)0x8010006A)
#define SCARD_W_WRONG_CHV ((LONG)0x8010006B)
#define SCARD_W_CHV_BLOCKED ((LONG)0x8010006C)
#define SCARD_W_EOF ((LONG)0x8010006D)
#define SCARD_W_CANCELLED_BY_USER ((LONG)0x8010006E)
#define SCARD_W_CARD_NOT_AUTHENTICATED ((LONG)0x8010006F)
#define SCARD_W_CACHE_ITEM_NOT_FOUND ((LONG)0x80100070)
#define SCARD_W_CACHE_ITEM_STALE ((LONG)0x80100071)
#define SCARD_W_CACHE_ITEM_TOO_BIG ((LONG)0x80100072)

#define SCARD_AUTOALLOCATE ((DWORD)(-1))

#define SCARD_SCOPE_USER 0
#define SCARD_SCOPE_SYSTEM 2

#define SCARD_PROTOCOL_UNDEFINED 0x00000000
#define SCARD_PROTOCOL_T0 0x00000001
#define SCARD_PROTOCOL_T1 0x00000002
#define SCARD_PROTOCOL_RAW 0x00010000

#define SCARD_SHARE_EXCLUSIVE 1
#define SCARD_SHARE_SHARED 2
#define SCARD_SHARE_DIRECT 3

#define SCARD_LEAVE_CARD 0
#define SCARD_RESET_CARD 1
#define SCARD_UNPOWER_CARD 2
#define SCARD_EJECT_CARD 3

#define SCARD_UNKNOWN 1
#define SCARD_ABSENT 2
#define SCARD_PRESENT 3
#define SCARD_SWALLOWED 4
#define SCARD_POWERED 5
#define SCARD_NEGOTIABLE 6
#define SCARD_SPECIFIC 7

#define SCARD_STATE_UNAWARE 0x00000000
#define SCARD_STATE_IGNORE 0x00000001
#define SCARD_STATE_CHANGED 0x00000002
#define SCARD_STATE_UNKNOWN 0x00000004
#define SCARD_STATE_UNAVAILABLE 0x00000008
#define SCARD_STATE_EMPTY 0x00000010
#define SCARD_STATE_PRESENT 0x00000020
#define SCARD_STATE_ATRMATCH 0x00000040
#define SCARD_STATE_EXCLUSIVE 0x00000080
#define SCARD_STATE_INUSE 0x00000100
#define SCARD_STATE_MUTE 0x00000200
#define SCARD_STATE_UNPOWERED 0x00000400

#define SCARD_ATTR_ATR_STRING 0x00090303

#define INFINITE 0xFFFFFFFF

#ifdef __cplusplus
}
#endif

#endif
