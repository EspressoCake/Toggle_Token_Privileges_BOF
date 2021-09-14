#pragma once

#include <windows.h>

/* Credit: @anthemtotheego */
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_CREATE 0x00000002
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
