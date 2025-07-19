#include "memory.h"
#include <core/framework.h>
#include <process/funcs.h>

bool safe_copy(void* dst, void* src, size_t size, uint32_t pid, uint32_t user_pid)
{
	SIZE_T bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS user_proc = process::get_by_id(user_pid, &status);
	if (!NT_SUCCESS(status)) return false;
	PEPROCESS target_proc = process::get_by_id(pid, &status);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(user_proc);
		return false;
	}

	if (MmCopyVirtualMemory(user_proc, src, target_proc, dst, size, KernelMode, &bytes) == STATUS_SUCCESS && bytes == size)
	{
		return true;
	}

	return false;
}

NTSTATUS memory::write_process_memory(uint32_t pid, uint32_t user_pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_written)
{

	//if (!safe_copy((void*)addr, (void*)buffer, size, pid, user_pid))
	//{
	//	return STATUS_FAIL_CHECK;
	//}

	//if (!addr || !pid || !buffer || !size)
	//{
	//	return 0;
	//}

	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS user_proc = process::get_by_id(user_pid, &status);
	if (!NT_SUCCESS(status)) return status;
	PEPROCESS target_proc = process::get_by_id(pid, &status);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(user_proc);
		return status;
	}

	size_t processed;
	status = memory::MmCopyVirtualMemory(user_proc, (void *)buffer, target_proc, (void *)addr, size, UserMode, &processed);

	ObDereferenceObject(user_proc);
	ObDereferenceObject(target_proc);

	if (!NT_SUCCESS(status)) return status;
	if (bytes_written) *bytes_written = processed;

	if (processed != size)
		return STATUS_FAIL_CHECK;
	return STATUS_SUCCESS;
}

NTSTATUS memory::read_process_memory(uint32_t pid, uint32_t user_pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_read)
{
	//if (!safe_copy((void*)addr, (void*)buffer, size, pid, user_pid))
	//{
	//	return STATUS_FAIL_CHECK;
	//}

	//if (!addr || !pid || !buffer || !size)
	//{
	//	return 0;
	//}

	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS user_proc = process::get_by_id(user_pid, &status);
	if (!NT_SUCCESS(status)) return status;
	PEPROCESS target_proc = process::get_by_id(pid, &status);
	if (!NT_SUCCESS(status)) return status;

	size_t processed;
	status = memory::MmCopyVirtualMemory(target_proc, (void *)addr, user_proc, (void *)buffer, size, UserMode, &processed);
	if (!NT_SUCCESS(status)) return status;
	if (bytes_read) *bytes_read = processed;

	if (processed != size)
		return STATUS_FAIL_CHECK;
	return STATUS_SUCCESS;
}