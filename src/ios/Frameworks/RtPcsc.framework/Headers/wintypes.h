/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

//  Copyright (c) 2013 Aktiv Co. All rights reserved.

#ifndef pcsc_ios_wintypes_h
#define pcsc_ios_wintypes_h

#include <stdint.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint8_t BYTE;
typedef BYTE* LPBYTE;
typedef const BYTE* LPCBYTE;
typedef ULONG DWORD;
typedef DWORD* LPDWORD;
typedef void* LPVOID;
typedef const void* LPCVOID;

typedef char* LPSTR;
typedef const char* LPCSTR;
typedef wchar_t* LPWSTR;
typedef const wchar_t* LPCWSTR;

#ifdef _UNICODE
#define TCHAR wchar_t
#define LPTSTR LPWSTR
#define LPCTSTR LPCWSTR
#else
#define TCHAR char
#define LPTSTR LPSTR
#define LPCTSTR LPCSTR
#endif

#ifdef __cplusplus
}
#endif

#endif
