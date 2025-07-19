# Driver Analysis: Kernel-Mode and User-Mode Components for Anti-Cheat Evasion

This document provides a comprehensive analysis of a kernel-mode driver and its accompanying user-mode client, designed for interaction with games protected by anti-cheat systems such as Easy Anti-Cheat (EAC). The analysis covers their architecture, key functionalities, and the advanced techniques employed to bypass common anti-cheat detections.

### I. Introduction

Modern anti-cheat systems operate by monitoring game processes and the system kernel for unauthorized modifications or suspicious activities. To circumvent these protections, cheat developers often employ a dual-component approach: a user-mode application that interacts with a kernel-mode driver. The kernel-mode driver, operating at a higher privilege level, can bypass many user-mode restrictions imposed by anti-cheats, enabling powerful memory manipulation and system interaction capabilities.

This project consists of two primary components:

- **Kernel-Mode Driver (EAC/driver):** Operates with elevated privileges in the Windows kernel, providing low-level access to system resources and other processes.
- **User-Mode Client (EAC/um):** A user-facing application that communicates with the kernel-mode driver to initiate and control cheating functionalities.

### II. User-Mode Client (`EAC/um`) Analysis

The user-mode client, primarily implemented in `um/main.cpp`, serves as the interface for the cheat. It communicates with the kernel-mode driver to perform privileged operations that would otherwise be restricted in user mode.

#### Key Characteristics:

- **Initialization and Communication:** The client utilizes a `kernel::driver` class to establish and manage communication with the kernel-mode driver. The `driver.init()` function is crucial for this initial handshake.
- **Process Attachment:** It attaches to the current process using `driver.attach(GetCurrentProcessId())`, indicating its intent to interact with game processes.
- **Memory Operations:** The client demonstrates the ability to:
  - **Get Process Base Address:** Retrieve the base memory address of a target process (`driver.get_process_base()`).
  - **Get Process Module Address:** Obtain the base address of specific DLLs (modules) loaded within a process (e.g., `kernel32.dll`, `win32u.dll`). This is critical for locating game code or data within loaded libraries.
  - **Read and Write Memory:** Perform read (`driver.read<int>(address)`) and write (`driver.write<int>(address, value)`) operations on arbitrary memory addresses within the target process. This is the core functionality for implementing various cheats (e.g., modifying health, ammo, coordinates).
  - **Buffer Operations:** Read and write larger blocks of memory using `driver.read_buffer()` and `driver.write_buffer()`, enabling the manipulation of arrays or structures.
- **Obfuscation:** The presence of `xorstr.h` in the user-mode client (and the kernel driver) suggests the use of string obfuscation. This technique encrypts strings at compile time and decrypts them at runtime, making it harder for anti-cheat systems to detect hardcoded strings like process names, module names, or function names through static analysis.

#### Communication Mechanism (Conceptual):

The user-mode client likely sends commands and data to the kernel-mode driver using a custom communication protocol, often leveraging the kernel hook for data transfer. For example, it might pass an operation code and relevant parameters (process ID, address, buffer, size) to the driver.

### III. Kernel-Mode Driver (`EAC/driver`) Analysis

The kernel-mode driver is the most critical component, operating in a privileged environment to perform actions that user-mode applications cannot. Its design focuses on stealth and bypassing anti-cheat mechanisms.

#### A. Core Functionality (`driver/core/`)

This directory houses the central logic of the driver, particularly its hooking mechanism.

- **API Hooking (`hook.h`, `hook.cpp`):**
  - **Target Function:** The driver primarily targets the `NtGdiPolyPolyDraw` function for hooking. This is a deliberate choice, as hooking less frequently monitored or less critical system calls can help avoid detection by anti-cheat systems that focus on common syscalls (e.g., `NtReadVirtualMemory`, `NtWriteVirtualMemory`).
  - **`hooked_fptr`:** This custom function replaces the original `NtGdiPolyPolyDraw`. It acts as a gateway for user-mode requests.
  - **Communication Channel:** The `hooked_fptr` receives a `fptr_data::kernel_com` structure as an argument. This structure serves as the primary communication channel from the user-mode client to the kernel driver. It encapsulates the desired operation, process IDs, memory addresses, and data buffers.
  - **Operational Dispatch:** Inside `hooked_fptr`, a `switch` statement dispatches various operations requested by the user-mode client, including:
    - `get_process_base`: Retrieves the base address of a process's image.
    - `get_process_module`: Finds the base address of a specific module (DLL) within a target process.
    - `read`: Performs memory read operations.
    - `write`: Performs memory write operations.
  - **Privilege Escalation & Context Swapping (`swap_process`):** The `swap_process` function is a highly advanced technique. It temporarily changes the execution context of the current thread to a different process by modifying the `KAPC_STATE` and, crucially, updating the `CR3` (Control Register 3). `CR3` holds the physical address of the Page Directory Base, which is essential for virtual-to-physical address translation. By changing `CR3` to the target process's page directory, the driver gains full access to the target process's virtual memory space, bypassing many traditional memory protection mechanisms and anti-cheat hooks. This operation is performed in kernel mode, making it invisible to user-mode anti-cheat monitoring.

#### B. Memory Management (`driver/memory/`)

This section handles sophisticated memory manipulation.

- **Virtual Memory Operations (`memory.h`, `memory.cpp`):**
  - **`read_process_memory` and `write_process_memory`:** These functions utilize `MmCopyVirtualMemory` to perform memory read and write operations between process virtual address spaces. `MmCopyVirtualMemory` is a kernel-mode function that allows copying data safely and efficiently between different process contexts, or between user-mode and kernel-mode buffers. The `UserMode` parameter used in the implementation indicates that the copy is performed as if from a user-mode context, but with kernel privileges. This method is generally considered safer and more robust than direct physical memory manipulation for typical memory operations.
- **Physical Memory Operations (`phys.h`, `phys.cpp`):**
  - **Direct Physical Access:** This driver takes an even more aggressive approach by providing functions to read (`ReadPhysicalAddress`) and write (`WritePhysicalAddress`) directly to physical memory. This is achieved using `MmCopyMemory` for reads and `MmMapIoSpaceEx` followed by `memcpy` for writes. Direct physical memory access bypasses the CPU's memory management unit (MMU) and virtual memory protections entirely, making it extremely difficult for anti-cheat systems to detect or prevent.
  - **Linear to Physical Address Translation (`TranslateLinearAddress`):** The `TranslateLinearAddress` function is crucial for this. It takes a virtual address and a process's Directory Table Base (`CR3`) and walks the page tables (PML4, PDPT, PD, PT) to determine the corresponding physical address. This enables the driver to access any virtual memory address of any process by first translating it to its physical equivalent.
  - **`CR3` Acquisition (`get_process_cr3`, `GetUserDirectoryTableBaseOffset`):** The driver includes logic to obtain the `CR3` of a target process. It even adapts to different Windows versions by dynamically determining the offset of the `DirectoryTableBase` within the `EPROCESS` structure using `GetUserDirectoryTableBaseOffset`. This version adaptability enhances the driver's longevity against OS updates.
  - **Wrapper Functions:** The `memory` namespace within `phys.cpp` provides wrapper functions (`read_process_memory`, `write_process_memory`) that leverage the physical memory read/write and address translation capabilities to offer process-agnostic memory manipulation based on PID.

#### C. Process Management (`driver/process/`)

This module provides basic but essential process interaction capabilities.

- **`get_by_id` (`funcs.h`, `proc_funcs.cpp`):** This function uses `PsLookupProcessByProcessId` to obtain a pointer to the `EPROCESS` structure of a given process ID. The `EPROCESS` structure contains vital information about a process in the kernel. This function is fundamental for various operations that require a direct handle to the target process.

#### D. System Utilities (`driver/system/`)

This section contains helper functions for system-level information gathering.

- **Module Information (`get_loaded_module`, `get_system_module`):** These functions retrieve the base addresses of loaded kernel modules (e.g., `win32k.sys`). This is critical for locating functions or data within these modules that the driver might need to hook or interact with. `get_system_module` uses `ZwQuerySystemInformation` for a robust way to enumerate system modules.
- **Pattern Scanning (`find_pattern`):** The driver includes robust pattern scanning (signature scanning) functionalities. This technique searches for specific byte sequences (patterns) within a module's memory. Pattern scanning is vital for locating functions or data that might not have fixed addresses across different game or OS versions, making the cheat more resilient to updates. The flexibility of using masks (`x` for exact, `?` for wildcard) allows for matching patterns even with varying bytes.
- **Exported Routine Lookup (`get_routine_address`):** This function uses `RtlFindExportedRoutineByName` to get the address of an exported function within a kernel image. This is a standard way for kernel modules to find and call functions exposed by other modules.

### IV. Anti-Cheat Evasion Strategies

The design of this kernel-mode driver incorporates several advanced techniques to evade anti-cheat systems:

1.  **Kernel-Mode Operations:** By operating in kernel mode, the driver inherently bypasses many user-mode anti-cheat protections, as anti-cheats have limited visibility and control over kernel-level activities.
2.  **API Hooking (`NtGdiPolyPolyDraw`):** Choosing a less commonly monitored system call for hooking makes detection more challenging. Many anti-cheats primarily focus on sensitive system calls related to memory access or process manipulation.
3.  **Process Context Swapping (`CR3` Manipulation):** The `swap_process` function, by directly manipulating `CR3`, allows the driver to seamlessly access the virtual memory of any target process. This is a powerful technique that can bypass anti-cheats that rely on standard `ReadProcessMemory`/`WriteProcessMemory` API monitoring.
4.  **Direct Physical Memory Access:** Reading and writing directly to physical memory is one of the most robust and difficult-to-detect memory manipulation methods. It completely bypasses virtual memory protections and any user-mode or even some kernel-mode hooks that operate at the virtual memory layer.
5.  **Dynamic Address Resolution (Pattern Scanning):** The use of pattern scanning ensures that the driver can locate critical game functions or data even if their addresses change due to game updates or re-compilations, making the cheat more persistent.
6.  **String Obfuscation (`xorstr.h`):** Obfuscating strings helps prevent static analysis of the driver and client binaries, making it harder for anti-cheat systems to identify known cheat signatures.

### V. Potential Visual Elements for the .md File

To make the `.md` file visually appealing and easier to understand, consider including the following elements:

- **Architecture Diagram (Mermaid):**
  - A flowchart or block diagram showing the interaction between the User-Mode Client, Kernel-Mode Driver, and the Target Game Process, highlighting the communication path (hooked API).
  - Example Mermaid code structure:
    ```mermaid
    graph TD
        A[User-Mode Client] --> B{Kernel-Mode Driver};
        B --> C[Game Process];
        B -- Physical Memory Access --> D[Physical Memory];
        B -- CR3 Manipulation --> E[MMU/Page Tables];
        C -- Anti-Cheat Monitoring --> F[Anti-Cheat System];
    ```
- **Code Snippets:**
  - Small, relevant code snippets from `hook.cpp` showing the `hooked_fptr` `switch` statement.
  - Snippets from `phys.cpp` illustrating `TranslateLinearAddress` or `ReadPhysicalAddress`/`WritePhysicalAddress`.
  - Snippet from `um/main.cpp` showing `driver.read()`/`driver.write()` calls.
- **Flowcharts for Key Operations:**
  - A flowchart illustrating the flow of a memory read operation, from the user-mode request to the kernel-mode driver, physical address translation, and actual memory access.
- **Call Stack Diagram:**
  - A simple diagram illustrating how a user-mode call might end up in the kernel driver's `hooked_fptr`.
- **Screenshot/Diagram of Memory Layout (Conceptual):**
  - A simplified diagram showing virtual memory space, page tables, and physical memory, with arrows indicating how the driver translates addresses and performs direct physical access.
