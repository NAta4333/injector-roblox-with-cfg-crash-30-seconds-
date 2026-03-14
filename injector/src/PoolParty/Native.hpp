#pragma once
#include <vector>
#include <Windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include "Misc.hpp"
#pragma comment(lib, "ntdll")

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
    PVOID KeyContext;
    PVOID ApcContext;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID  Key;
} FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	unsigned long Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	unsigned __int64 MaxMessageLength;
	unsigned __int64 MemoryBandwidth;
	unsigned __int64 MaxPoolUsage;
	unsigned __int64 MaxSectionSize;
	unsigned __int64 MaxViewSize;
	unsigned __int64 MaxTotalSectionSize;
	ULONG DupObjectTypes;
#ifdef _WIN64
	ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			USHORT DataLength;
			USHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			USHORT Type;
			USHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize;
		ULONG CallbackId;
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE {
	PORT_MESSAGE PortHeader;
	BYTE PortMessage[1000];
} ALPC_MESSAGE, * PALPC_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
{
	PVOID CompletionKey;
	HANDLE CompletionPort;
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG Version;
	ULONG Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ACCESS_MASK GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef enum
{
	SeDebugPrivilege = 20
} PRIVILEGES;

typedef enum
{
	AlpcAssociateCompletionPortInformation = 2
} ALPC_PORT_INFOCLASS;

typedef enum
{
	FileReplaceCompletionInformation = 61
} FILE_INFOCLASS;

typedef enum
{
	ProcessHandleInformation = 51
} PROCESS_INFOCLASS;

EXTERN_C
NTSTATUS NTAPI ZwAssociateWaitCompletionPacket(
	_In_ HANDLE WaitCompletionPacketHandle,
	_In_ HANDLE IoCompletionHandle,
	_In_ HANDLE TargetObjectHandle,
	_In_opt_ PVOID KeyContext,
	_In_opt_ PVOID ApcContext,
	_In_ NTSTATUS IoStatus,
	_In_ ULONG_PTR IoStatusInformation,
	_Out_opt_ PBOOLEAN AlreadySignaled
);

EXTERN_C
NTSTATUS NTAPI ZwSetInformationFile(
	_In_ HANDLE hFile,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ PVOID FileInformation,
	_In_ ULONG Length,
	_In_ ULONG FileInformationClass
);

EXTERN_C
NTSTATUS NTAPI NtAlpcCreatePort(
	_Out_ PHANDLE PortHandle,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);

EXTERN_C
NTSTATUS NTAPI NtAlpcSetInformation(
	_In_ HANDLE PortHandle,
	_In_ ULONG PortInformationClass,
	_In_opt_ PVOID PortInformation,
	_In_ ULONG Length
);

EXTERN_C
NTSTATUS NTAPI NtAlpcConnectPort(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
	_In_ DWORD ConnectionFlags,
	_In_opt_ PSID RequiredServerSid,
	_In_opt_ PPORT_MESSAGE ConnectionMessage,
	_Inout_opt_ PSIZE_T ConnectMessageSize,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	_In_opt_ PLARGE_INTEGER Timeout
);

EXTERN_C
NTSTATUS NTAPI RtlAdjustPrivilege(
	_In_ ULONG Privilege,
	_In_ BOOLEAN Enable,
	_In_ BOOLEAN CurrentThread,
	_Out_ PBOOLEAN Enabled
);

EXTERN_C
NTSTATUS NTAPI ZwSetIoCompletion(
	_In_ HANDLE IoCompletionHandle,
	_In_opt_ PVOID KeyContext,
	_In_opt_ PVOID ApcContext,
	_In_ NTSTATUS IoStatus,
	_In_ ULONG_PTR IoStatusInformation
);

EXTERN_C
NTSTATUS NTAPI NtSetTimer2(
	_In_ HANDLE TimerHandle,
	_In_ PLARGE_INTEGER DueTime,
	_In_opt_ PLARGE_INTEGER Period,
	_In_ PT2_SET_PARAMETERS Parameters
);

void w_ZwAssociateWaitCompletionPacket(HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN);
void w_ZwSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
HANDLE w_NtAlpcCreatePort(POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES);
void w_NtAlpcSetInformation(HANDLE, ULONG, PVOID, ULONG);
HANDLE w_NtAlpcConnectPort(PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, DWORD, PSID, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER);
BOOLEAN w_RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN);
void w_ZwSetIoCompletion(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
void w_NtSetTimer2(HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PT2_SET_PARAMETERS);

inline void NT_SUCCESS_OR_RAISE(std::string f, NTSTATUS s)
{
	if (!NT_SUCCESS(s)) throw std::runtime_error(GetLastErrorString(f, RtlNtStatusToDosError(s)));
}

template <typename TQueryFunction, typename... TQueryFunctionArgs>
std::vector<BYTE> w_QueryInformation(const std::string fn, TQueryFunction qf, TQueryFunctionArgs... qa)
{
	ULONG l = 0;
	auto s = STATUS_INFO_LENGTH_MISMATCH;
	std::vector<BYTE> i;
	do {
		i.resize(l);
		s = qf(qa..., i.data(), l, &l);
	} while (STATUS_INFO_LENGTH_MISMATCH == s);
	if (!NT_SUCCESS(s)) throw std::runtime_error(GetLastErrorString(fn, RtlNtStatusToDosError(s)));
	return i;
}
