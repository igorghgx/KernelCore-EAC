#include "hook.h"
#include <memory/memory.h> //read_process_memory, write_process_memory
#include <process/funcs.h>
#include <system/funcs.h>
#include <intrin.h>

uintptr_t swap_process(uintptr_t new_process)
{
	auto usermodeThread = (uintptr_t)KeGetCurrentThread();
	if (!usermodeThread)
		return STATUS_UNSUCCESSFUL;

	auto apc_state = *(uintptr_t*)(usermodeThread + 0x98);
	auto old_process = *(uintptr_t*)(apc_state + 0x20);
	*(uintptr_t*)(apc_state + 0x20) = new_process;

	auto dir_table_base = *(uintptr_t*)(new_process + 0x28);
	__writecr3(dir_table_base);

	return old_process;
}


NTSTATUS GetModuleBaseAddress(int processId, const char* moduleName, uint64_t* baseAddress)
{
	ANSI_STRING ansiString;
	UNICODE_STRING compareString;
	KAPC_STATE state;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = NULL;
	system::PPEB pPeb = NULL;

	RtlInitAnsiString(&ansiString, moduleName);
	RtlAnsiStringToUnicodeString(&compareString, &ansiString, TRUE);

	printf("Looking for module %d\n", processId);

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processId, &process)))
		return STATUS_UNSUCCESSFUL;

	printf("Found process %d\n", processId);

	auto o_process = swap_process((uintptr_t)process);
	pPeb = process::PsGetProcessPeb(process);

	if (pPeb)
	{
		system::PPEB_LDR_DATA pLdr = (system::PPEB_LDR_DATA)pPeb->Ldr;

		if (pLdr)
		{
			for (PLIST_ENTRY listEntry = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
				listEntry != &pLdr->InLoadOrderModuleList;
				listEntry = (PLIST_ENTRY)listEntry->Flink) {

				system::PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(listEntry, system::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				printf("%wZ\n", pEntry->BaseDllName);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, &compareString, TRUE) == 0)
				{
					*baseAddress = (uint64_t)pEntry->DllBase;
					status = STATUS_SUCCESS;
					break;
				}
			}
		}
	}
	swap_process(o_process);
	RtlFreeUnicodeString(&compareString);
	return status;
}

__int64 __fastcall core_hook::hooked_fptr(void* a1)
{
	if (!a1 || ExGetPreviousMode() != UserMode)
	{
		printf("!a1 || ExGetPreviousMode() != UserMode fail. arguments: %16X\n", a1);
		return core_hook::o_function_qword_1(a1);
	}

	fptr_data::kernel_com *com = (fptr_data::kernel_com *)a1;
	com->error = fptr_data::kernel_err::no_error;
	
	switch (com->opr)
	{
		case fptr_data::kernel_opr::get_process_base:
		{
			NTSTATUS status = STATUS_SUCCESS;

			PEPROCESS proc = process::get_by_id(com->target_pid, &status);
			if (!NT_SUCCESS(status))
			{
				com->error = fptr_data::kernel_err::invalid_process;
				com->success = false;

				printf("get_process_base failed: invalid process.\n");
				return 0;
			}

			com->buffer = (uintptr_t)process::PsGetProcessSectionBaseAddress(proc);
			ObDereferenceObject(proc);
			break;
		}
		case fptr_data::kernel_opr::get_process_module:
		{
			// Inputs
			if (!com->target_pid)
			{
				com->error = fptr_data::kernel_err::invalid_data;
				com->success = false;
				printf("get_process_module failed: no valid process id given.\n");
				break;
			}


			uintptr_t buffer = 0;
			com->buffer = 0;
			if ( NT_SUCCESS( GetModuleBaseAddress( com->target_pid, com->name, &buffer ) ) )
				com->buffer = buffer;
			break;
			
			break;
		}

		case fptr_data::kernel_opr::write:
		{
			if (!NT_SUCCESS(memory::write_process_memory(com->target_pid, com->user_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				com->error = fptr_data::kernel_err::invalid_data;
				printf("write failed: invalid data.\n");
				return 0;
			}
			break;
		}
		case fptr_data::kernel_opr::read:
		{
			if (!NT_SUCCESS(memory::read_process_memory(com->target_pid, com->user_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				com->error = fptr_data::kernel_err::invalid_data;
				printf("read failed: invalid data.\n");
				return 0;
			}
			break;
		}

		default:
		{
			com->success = false;
			com->error = fptr_data::kernel_err::no_operation;
			printf("(%p) failed: unknown operation.\n", com->opr);
			return 0;
		}
	}

	com->success = true;
	printf("kernel operation completed successfully.\n");
	return 0;
}