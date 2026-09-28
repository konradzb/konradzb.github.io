---
layout: post
tags: [soopr, config]
---

# DLL Injection: A Comprehensive Security Perspective

I created this short paper to sumerize my knowledge about DLL and DLL Injection in one place. Its much easier to exploit something from time to time when you don't have to remind every detail again and agian :). There is no fancy stuff, the idea was to create geenral guide to help myself when I came across DLL Injection in the future. For example on Windows we have User32.dll, which exports functions related to user interface. 

Applications can be devided into multiple modules, each module have its seperate DLL file, which is loaded seperatly when main application (.exe file) requires it. It is more eficient for system to maintain mudular application, but I think more important is fact, that is also easier to maintain applications code when its devided into modules.

## 1. What is a DLL?

As we can read on (oficial microsoft page)[https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/dynamic-link-library#more-information] - "a DLL is a library that contains code and data that can be used by more than one program at the same time". It's more eficient to place your code in DLL when you know it will be used in multiple places. Unlike static libraries that are embedded into an executable at compile time, DLL will be loaded when particular function is called inside the code.


### 1.2 Structure and Portable Executable (PE) Format

Structure of Portable Executable (PE) is quite complicated and I am not going to copy the inforamtion from oficial microsoft website, you can find (more information there)[https://learn.microsoft.com/en-us/windows/win32/debug/pe-format]. 
Great visualization was done in the picture below, where simple.exe was described, however the structure is similar to the DLL file 

https://github.com/corkami/pics/blob/master/binary/pe101/pe101.png

#TODO - read the blog post and complete this section


### 1.3 How DLLs Are Built

The DLL compilation process involves two primary steps:

**Step 1 - Compilation**: Source files are compiled into object files (`.obj` files). During this phase, the compiler generates machine code and includes metadata about external dependencies.

**Step 2 - Linking**: Object files are linked together with any dependent libraries to create the final DLL file. The linker:
- Resolves external symbol references
- Generates the Import Address Table
- Creates the Export Address Table with all exported function names
- Marks functions for export using either `__declspec(dllexport)` or a Module Definition (`.def`) file

The **export mechanism** defines which functions are accessible to external applications. Functions must be explicitly marked for export; all other functions remain private to the DLL.

#TODO - finalize this section later

---

## 2. DLL Injection: Mechanism and Execution

### 2.1 Definition

**DLL Injection** is a technique used to introduce a Dynamic Link Library into the address space of a running process, thereby altering the behavior of that process without modifying its original code. The injected DLL executes with the same privileges as the target process and can perform arbitrary operations within that context.

### 2.2 How DLL Injection Works - General overview

The DLL injection process follows a systematic approach:

1. **Process Identification**: The attacker identifies the target process using programs like (Process Monitor)[https://learn.microsoft.com/en-us/sysinternals/downloads/procmon] (Procmon.exe) into which the DLL will be injected. This is typically a legitimate system process or application with elevated privileges.

The targeted process has to call the DLL, which can be later edited by the low privileged user. Often times the the vulnrable application call DLL which is not there - in the Process Monitor this is

2. **Memory Allocation**: 

3. **DLL Path Injection**: The path to the malicious DLL is written into the allocated memory within the target process.

4. **Thread Creation**: A remote thread is created within the target process using `CreateRemoteThread()`, instructing it to load the DLL via `LoadLibrary()` or similar functions.

5. **Code Execution**: The injected DLL's `DllMain` function is called automatically by the Windows loader, executing the malicious payload.

### 2.3 Injection Methods

**CreateRemoteThread + LoadLibrary**: The most straightforward method, creating a remote thread that calls `LoadLibrary()` to load the DLL from disk.

**Reflective DLL Injection**: A more sophisticated technique that loads a DLL entirely from memory without relying on standard Windows API functions. This method is particularly stealthy as it avoids creating obvious artifacts and bypasses some security monitoring.

**SetWindowsHookEx Injection**: Exploits Windows hook mechanisms to inject code into specific process types.

**Registry-based Injection**: Leverages registry entries to force processes to load specific DLLs at startup.

---

## 3. System DLLs (LOLBINs) vs Custom Application DLLs

### 3.1 System DLLs and Living-Off-The-Land Binaries (LOLBINs)

**System DLLs** are Microsoft-signed libraries that ship with Windows or are downloaded directly from Microsoft. These include critical components like `Kernel32.dll`, `User32.dll`, `Advapi32.dll`, and `Shell32.dll`. System DLLs are typically located in:
- `%SystemRoot%\System32` (64-bit DLLs)
- `%SystemRoot%\SysWOW64` (32-bit DLLs on 64-bit systems)

**Living-Off-The-Land Binaries (LOLBINs)** are legitimate, signed Windows executables and DLLs that can be abused for purposes beyond their intended functionality. These binaries possess "unexpected" functionality that makes them valuable for attackers:
- They are inherently trusted by security solutions
- They are already present on every Windows system
- They often have elevated privileges
- They are difficult to detect during abuse

Examples of commonly abused LOLBINs include `Rundll32.exe` (executes DLL functions), `Regsvcs.exe`, `Regasm.exe`, `Mshta.exe`, and `Cscript.exe`. A comprehensive list of LOLBINs can be found at the LOLBAS Project repository.

### 3.2 Custom Application DLLs

Custom application DLLs are created by software vendors for specific purposes and are typically:
- **Unsigned** or signed by the vendor (not by Microsoft)
- Located in application-specific directories rather than system directories
- Subject to varying security policies
- More vulnerable to modification and hijacking

The distinction is critical for both defenders and attackers. Defenders monitor for unexpected usage of system DLLs, while attackers prefer to abuse LOLBINs to blend in with legitimate activity.

---

## 4. Detection Mechanisms: Procmon and Process Explorer

### 4.1 Process Monitor (Procmon)

**Process Monitor (Procmon)** is a real-time Windows system monitoring tool from Sysinternals that captures system calls, registry operations, and file I/O operations. For DLL-related troubleshooting:

**Detecting Missing DLLs**:
- Filter for the target process
- Set filters for operations: `Operation is Load Image` OR `Operation is CreateFile`
- Look for results with `NAME NOT FOUND` status
- Examine the file path to identify which DLL failed to load
- The tool displays the search order used by Windows, showing each directory checked

**Key indicators of missing DLLs**:
- Multiple repeated `CreateFile` operations with `NAME NOT FOUND` status for the same filename
- The path shows Windows searching through standard directories (`System32`, `SysWOW64`, application directory)
- After exhausting all search paths, a final `NAME NOT FOUND` result indicates loading failure

Procmon also helps identify:
- 32-bit vs 64-bit applications (by examining which system DLL directories are searched)
- DLL load order and dependencies
- Abnormal DLL loading from unexpected locations

### 4.2 Process Explorer

**Process Explorer**, another Sysinternals tool, provides a hierarchical view of running processes with detailed information about loaded DLLs and open files. For DLL analysis:

**DLL Detection Capabilities**:
- View all DLLs loaded by a specific process in the lower panel
- See the full path of each loaded DLL
- Integrate with VirusTotal to check if loaded DLLs are flagged as malicious
- Identify DLL version mismatches or unusual load locations
- Detect DLL injection by observing unexpected DLLs loaded into legitimate processes

**Detection advantages**:
- Real-time monitoring without application restart
- Visual representation of process hierarchies
- Quick identification of suspicious processes by resource consumption (CPU, memory, I/O)
- Hash-based malware detection via VirusTotal integration

**Workflow for detecting potential DLL injection**:
1. Sort processes by resource consumption to identify suspicious activity
2. Expand a suspicious process to view its loaded DLLs
3. Check DLL file paths for non-standard locations
4. Verify DLL hashes against VirusTotal
5. Examine parent-child process relationships

---

## 5. DLL Sideloading: The Stealthy Injection Vector

### 5.1 Definition and Mechanism

**DLL Sideloading**, also known as **DLL search-order hijacking**, is a technique where an attacker places a malicious DLL in the same directory as a legitimate, signed executable. When the executable launches, Windows searches for required DLLs following a specific search order:

1. The directory from which the application was loaded (first priority)
2. The system directory
3. The Windows directory
4. The directories in the PATH environment variable

By exploiting this search order, the attacker's malicious DLL is found and loaded instead of the legitimate system DLL.

### 5.2 Why DLL Sideloading is Effective

**Evasion advantages**:
- The process tree shows execution of a legitimate, signed binary (not malware)
- The parent process is often trusted
- Signed binaries face less scrutiny from security solutions
- No registry modifications or suspicious process creation
- Appears as normal application behavior

**Real-world example**: An attacker copies both a legitimate `explorer.exe` and a malicious `shell32.dll` to a user-writable directory. When the user executes the legitimate binary from that location, it loads the malicious DLL first, executing the attacker's payload while the legitimate application either crashes or continues normally (depending on implementation).

### 5.3 Detection Challenges

DLL sideloading is difficult to detect because:
- Legitimate binaries are being executed
- The attack doesn't generate obvious suspicious behavior
- Standard application execution appears normal
- File signatures are valid (the executable is legitimate)

---

## 6. DLL Proxying: Advanced Stealthy Evasion

### 6.1 Definition

**DLL Proxying** is an advanced technique combining DLL sideloading with **export forwarding**. Instead of simply loading a malicious DLL, the proxy DLL forwards all exported function calls to the legitimate original DLL while executing a malicious payload. This ensures the target application functions normally, avoiding crashes or suspicious behavior.

### 6.2 How DLL Proxying Works

The process involves creating a wrapper DLL that:
1. Exports all the same functions as the original DLL
2. Forwards function calls to the legitimate DLL
3. Executes malicious code in its `DllMain` entry point

**Export Forwarding Mechanism**: Instead of containing actual function implementations, the Export Address Table contains forwarders—strings that redirect to functions in another DLL. For example:

```
EXPORTS
    GetFileVersionInfoA = SHCore.dll.GetFileVersionInfoA
    GetFileVersionInfoW = SHCore.dll.GetFileVersionInfoW
    CommandLineToArgvW = SHCore.dll.CommandLineToArgvW
```

When an application calls `GetFileVersionInfoA`, the Windows loader automatically redirects the call to `SHCore.dll.GetFileVersionInfoA`.

### 6.3 Why DLL Proxying is Necessary

**Without Proxying**:
- Target application expects specific function exports
- If the malicious DLL doesn't provide these functions, the application crashes
- Crash is suspicious and easily detected
- Attacker's presence becomes obvious

**With Proxying**:
- All expected functions are available (forwarded to legitimate DLL)
- Application functions normally
- Malicious payload executes silently in the background
- Behavior appears completely legitimate to users and security tools

**Historical precedent**: The infamous Stuxnet malware used DLL proxying extensively to maintain stealth while executing its mission.

---

## 7. DLL Compilers and Build Tools

### 7.1 Compilation Tools

Several compilers can be used to build DLLs on Windows:

**Microsoft Visual C++ (MSVC)**: The official Microsoft compiler, integrated with Visual Studio. Provides comprehensive DLL development features and is the industry standard.

**GCC/MinGW**: The GNU Compiler Collection compiled for Windows (MinGW - Minimalist GNU for Windows). Available as an open-source alternative with no telemetry concerns.

**Intel DPC++/C++ Compiler**: An optimizing compiler supporting various hardware architectures.

**Clang**: LLVM-based compiler with Windows support.

### 7.2 Build Process Using MSVC

**Step 1 - Create Header File**:
```cpp
#pragma once

#ifdef MYDLL_EXPORTS
#define MYDLL_API __declspec(dllexport)
#else
#define MYDLL_API __declspec(dllimport)
#endif

extern "C" MYDLL_API int Add(int a, int b);
extern "C" MYDLL_API int Multiply(int a, int b);
```

**Step 2 - Implement Functions**:
```cpp
#define MYDLL_EXPORTS
#include "mydll.h"

int Add(int a, int b) {
    return a + b;
}

int Multiply(int a, int b) {
    return a * b;
}
```

**Step 3 - Configure Project**:
- Set project type to "Dynamic Library"
- Define `MYDLL_EXPORTS` in preprocessor definitions
- Link against necessary libraries

### 7.3 Build Process Using GCC/MinGW

**Compilation**:
```bash
gcc -c source.cpp -o source.o
```

**Linking**:
```bash
gcc -shared -o mydll.dll source.o -Wl,--out-implib,libmydll.a
```

The `-shared` flag creates a DLL instead of an executable, and `--out-implib` generates an import library for linking applications.

---

## 8. How to Compile Your Own DLL

### 8.1 Complete Example Using Visual Studio

**Create the Project**:
1. Launch Visual Studio
2. Create new project → Windows Desktop → Dynamic-Link Library (DLL)
3. Name the project (e.g., "MathLibrary")

**Header File (MathLibrary.h)**:
```cpp
#pragma once

#ifdef MATHLIBRARY_EXPORTS
#define MATHLIBRARY_API __declspec(dllexport)
#else
#define MATHLIBRARY_API __declspec(dllimport)
#endif

extern "C" {
    MATHLIBRARY_API int Add(int a, int b);
    MATHLIBRARY_API int Subtract(int a, int b);
    MATHLIBRARY_API int Multiply(int a, int b);
    MATHLIBRARY_API int Divide(int a, int b);
}
```

**Implementation File (MathLibrary.cpp)**:
```cpp
#include "pch.h"
#define MATHLIBRARY_EXPORTS
#include "MathLibrary.h"

int Add(int a, int b) { return a + b; }
int Subtract(int a, int b) { return a - b; }
int Multiply(int a, int b) { return a * b; }
int Divide(int a, int b) { return b != 0 ? a / b : 0; }
```

**Compilation**:
1. Set build configuration to Release or Debug
2. Select target platform (x64 or Win32)
3. Build → Build Solution
4. DLL will be created in the `\Release` or `\Debug` folder

### 8.2 Using DEF Files for Export Control

For more granular control over exports, create a `.def` file:

**MathLibrary.def**:
```
LIBRARY MathLibrary

EXPORTS
    Add             @1
    Subtract        @2
    Multiply        @3
    Divide          @4
```

Then configure the project linker to use this file in Project Properties → Linker → Input → Module Definition File.

---

## 9. DLL Loading: Static vs Dynamic Loading

### 9.1 Static (Load-Time) Linking

**Definition**: When an application uses load-time dynamic linking, all required DLLs are specified at link time and loaded automatically when the process starts.

**Process**:
1. During compilation/linking, the application's import table is populated with DLL names
2. When the application launches, the Windows loader examines the import table
3. Each listed DLL is located and loaded into memory
4. The Import Address Table is populated with actual runtime addresses
5. Application execution begins only after all dependencies are resolved

**Advantages**:
- Simple, straightforward implementation
- All dependencies resolved before execution
- Linker catches missing imports at build time

**Disadvantages**:
- Application fails to start if any DLL is missing
- Less flexible runtime behavior
- Larger initial startup time

**Implementation**:
```cpp
#include "MathLibrary.h"  // Import library linked at build time

int main() {
    int result = Add(5, 3);  // Function available immediately
    return 0;
}
```

### 9.2 Dynamic (Run-Time) Linking

**Definition**: When an application uses run-time dynamic linking, DLLs are explicitly loaded during execution using API calls like `LoadLibrary()` or `LoadLibraryEx()`.

**Process**:
1. Application calls `LoadLibrary("DllName.dll")`
2. The specified DLL is located using the DLL search order
3. DLL is loaded into memory
4. `GetProcAddress()` retrieves the address of specific exported functions
5. Functions can now be called through obtained addresses

**Advantages**:
- Flexible runtime behavior
- Application can function with missing optional DLLs
- Allows choosing alternative implementations at runtime
- Can be used for plugin architectures

**Disadvantages**:
- More complex implementation
- Runtime errors if DLL not found
- Requires explicit error handling

**Implementation**:
```cpp
#include <windows.h>

typedef int (*AddFunction)(int, int);

int main() {
    HMODULE hDll = LoadLibrary(L"MathLibrary.dll");
    if (hDll == NULL) {
        // Handle error - DLL not found
        return 1;
    }

    AddFunction Add = (AddFunction)GetProcAddress(hDll, "Add");
    if (Add == NULL) {
        // Handle error - function not found
        FreeLibrary(hDll);
        return 1;
    }

    int result = Add(5, 3);
    FreeLibrary(hDll);
    return 0;
}
```

### 9.3 Memory-Mapped Loading (Advanced)

Advanced applications may opt to memory-map a DLL file directly, providing finer control over memory layout and loading behavior. This is rarely used in typical applications but offers maximum flexibility for specialized scenarios.

---

## 10. DLL Main Limitations and Best Practices

### 10.1 DllMain Entry Point

The `DllMain` function is an optional entry point called by the system when:
- A process loads the DLL (DLL_PROCESS_ATTACH)
- A process unloads the DLL (DLL_PROCESS_DETACH)
- A new thread is created in a process with the DLL loaded (DLL_THREAD_ATTACH)
- A thread terminates normally (DLL_THREAD_DETACH)

**Basic Structure**:
```cpp
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,     // DLL module handle
    DWORD fdwReason,        // Reason for calling
    LPVOID lpvReserved)     // Reserved parameter
{
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Process-wide initialization
            break;
        case DLL_THREAD_ATTACH:
            // Thread-specific initialization
            break;
        case DLL_THREAD_DETACH:
            // Thread-specific cleanup
            break;
        case DLL_PROCESS_DETACH:
            // Process-wide cleanup
            break;
    }
    return TRUE;
}
```

### 10.2 Critical Limitations

**The Loader Lock Problem**: `DllMain` is called while the Windows loader lock is held. This lock ensures thread-safe DLL loading but severely restricts what can be done safely within `DllMain`.

**Functions FORBIDDEN in DllMain** (directly or indirectly):
- `LoadLibrary()` / `LoadLibraryEx()` - Can cause deadlock or crash
- `GetStringTypeA()`, `GetStringTypeEx()`, `GetStringTypeW()` - Can deadlock
- Thread synchronization calls - Risk of deadlock
- Registry functions - Can deadlock
- `CreateProcess()` - May load another DLL, causing complications
- `ExitThread()` - Can cause loader lock to be reacquired, creating deadlock
- `CreateThread()` - Risky without proper synchronization
- User32.dll or Gdi32.dll functions - Many load other DLLs
- Managed code (.NET) - Unsafe in DllMain context
- Shell/known folder APIs - Can cause thread synchronization deadlocks
- Named object creation - Terminal Services DLL dependencies
- CRT memory functions - CRT may not be initialized

**Safe Operations in DllMain**:
- Initialize static data structures at compile time
- Create and initialize synchronization objects
- Allocate memory for dynamic data structures
- Set up thread local storage (TLS)
- Open, read from, and write to files
- Call Kernel32.dll functions (except those listed above)
- Set global pointers to NULL

### 10.3 Best Practices

**1. Minimize DllMain Work**:
The ideal `DllMain` is an empty stub. Postpone initialization as much as possible using lazy initialization techniques. Initialization that occurs outside the loader lock is much safer.

**2. Early Failure Detection**:
Some initializations must occur immediately (e.g., validating configuration files). These should be attempted and fail quickly rather than wasting resources.

**3. Lazy Initialization**:
Perform complex initialization the first time functions are actually called, not in `DllMain`. This increases application robustness significantly.

**4. Lock Order Discipline**:
If using synchronization primitives, define a strict lock hierarchy with the loader lock at the highest level. Never acquire locks in conflicting order.

**5. Thread Synchronization**:
Avoid waiting on threads from within `DllMain`. If a DLL creates worker threads, synchronization during unload is complex. Best practice: set an event signaling thread to exit, and let the thread clean itself up.

**6. Handle Process Exit Carefully**:
At process exit, all threads are forcibly cleaned up and memory may be inconsistent. Save persistent state before this occurs. The ideal `DLL_PROCESS_DETACH` handler is empty for process termination cases.

**7. Use Application Verifier**:
The Windows Application Verifier tool can catch the most common `DllMain` errors during development and testing.

**Example of Safe DllMain**:
```cpp
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved)
{
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Only initialize truly critical items
            // Post other initialization to first function call
            DisableThreadLibraryCalls(hinstDLL);
            break;

        case DLL_PROCESS_DETACH:
            // Don't do cleanup at process exit
            // (lpvReserved != nullptr indicates process termination)
            if (lpvReserved != nullptr)
                break;
            // Safe to clean up during explicit unload
            break;
    }
    return TRUE;
}
```

---

## Conclusion

DLL Injection and related techniques represent a complex intersection of Windows architecture, legitimate development practices, and sophisticated attack vectors. Understanding DLLs from first principles—their structure, loading mechanisms, and security implications—is essential for both defensive and offensive security practitioners.

The progression from basic DLL injection through DLL sideloading to DLL proxying demonstrates how attackers leverage legitimate system features to achieve their goals while evading detection. System administrators and security professionals must employ layered detection strategies using tools like Process Monitor and Process Explorer, combined with behavioral analysis and vigilant monitoring of process execution.

For developers, adherence to DLL best practices—particularly around `DllMain` limitations and lazy initialization—significantly reduces vulnerability to injection attacks and improves overall application robustness. Understanding the distinction between static and dynamic linking, proper export mechanisms, and the implications of DLL search order is crucial for building secure Windows applications.

As threats evolve, continued education on these mechanisms and adoption of advanced detection techniques will remain critical for maintaining security posture in Windows environments.

---

## References

- [What is a DLL](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/dynamic-link-library)
- [PE Format - documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE Format - picture](https://github.com/corkami/pics/blob/master/binary/pe101/pe101.png)
- [Dive into PE Format](https://0xrick.github.io/win-internals/pe1/)
- MITRE ATT&CK: T1055.001 - Dynamic-link Library Injection
- LOLBAS Project: Living Off The Land Binaries and Scripts
- Sysinternals Tools Documentation: Process Monitor and Process Explorer
- Windows PE Format Specifications and Loader Internals


### TODO:
- what is DOS mode?