#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>

#define SW2_SEED 0xB1D2CD0A
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(PCSTR FunctionName);
BOOL SW2_PopulateSyscallList();
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;


#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif




typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS NtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL);

EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtTestAlert();

EXTERN_C NTSTATUS NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtSuspendProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount);

EXTERN_C NTSTATUS NtResumeProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext);

EXTERN_C NTSTATUS NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context);

EXTERN_C NTSTATUS NtClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

EXTERN_C NTSTATUS NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

EXTERN_C NTSTATUS NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress);

EXTERN_C NTSTATUS NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

#endif


// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW2_SYSCALL_LIST SW2_SyscallList = {0,1};

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

BOOL SW2_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

    PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}
#define ZwCreateProcess NtCreateProcess
__asm__("NtCreateProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x045973678\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateThreadEx NtCreateThreadEx
__asm__("NtCreateThreadEx: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x024B7640E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A5ABA627\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0102E8925\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwTestAlert NtTestAlert
__asm__("NtTestAlert: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C8452ADB\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenThread NtOpenThread
__asm__("NtOpenThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01EBE819D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSuspendProcess NtSuspendProcess
__asm__("NtSuspendProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x021C70268\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSuspendThread NtSuspendThread
__asm__("NtSuspendThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x010CF5E65\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwResumeProcess NtResumeProcess
__asm__("NtResumeProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x033915C02\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwResumeThread NtResumeThread
__asm__("NtResumeThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0635E67C5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwGetContextThread NtGetContextThread
__asm__("NtGetContextThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x014BEDE10\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwSetContextThread NtSetContextThread
__asm__("NtSetContextThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0900F8EB5\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwClose NtClose
__asm__("NtClose: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x092C58F44\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x045D7716B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWriteVirtualMemory NtWriteVirtualMemory
__asm__("NtWriteVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0C391C803\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x084146274\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwProtectVirtualMemory NtProtectVirtualMemory
__asm__("NtProtectVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F1ADC90A\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__("NtFreeVirtualMemory: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0BE289488\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQuerySystemInformation NtQuerySystemInformation
__asm__("NtQuerySystemInformation: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x04D6A53C7\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryDirectoryFile NtQueryDirectoryFile
__asm__("NtQueryDirectoryFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0A2394838\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationFile NtQueryInformationFile
__asm__("NtQueryInformationFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0B80E5018\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationProcess NtQueryInformationProcess
__asm__("NtQueryInformationProcess: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x09F1C784E\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueryInformationThread NtQueryInformationThread
__asm__("NtQueryInformationThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0082ECD77\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwCreateSection NtCreateSection
__asm__("NtCreateSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x01DB2312C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwOpenSection NtOpenSection
__asm__("NtOpenSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x03692580B\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwMapViewOfSection NtMapViewOfSection
__asm__("NtMapViewOfSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x0F4AEF43D\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwUnmapViewOfSection NtUnmapViewOfSection
__asm__("NtUnmapViewOfSection: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x00C972CD9\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x067ED736C\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwDeviceIoControlFile NtDeviceIoControlFile
__asm__("NtDeviceIoControlFile: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x029392793\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwQueueApcThread NtQueueApcThread
__asm__("NtQueueApcThread: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x018BF1211\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
#define ZwWaitForMultipleObjects NtWaitForMultipleObjects
__asm__("NtWaitForMultipleObjects: \n\
	mov [rsp +8], rcx\n\
	mov [rsp+16], rdx\n\
	mov [rsp+24], r8\n\
	mov [rsp+32], r9\n\
	sub rsp, 0x28\n\
	mov ecx, 0x013B92713\n\
	call SW2_GetSyscallNumber\n\
	add rsp, 0x28\n\
	mov rcx, [rsp +8]\n\
	mov rdx, [rsp+16]\n\
	mov r8, [rsp+24]\n\
	mov r9, [rsp+32]\n\
	mov r10, rcx\n\
	syscall\n\
	ret\n\
");
