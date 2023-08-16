---
title: "Quick Tip: Stop Using GetProcAddress and Let the Linker Do the Job for You"
date: 2023-08-15 21:00:00 -0300

categories: [Programming]
tags: [Programming, Windows Internals]
---

For a long time, Linux was my primary subject of study. I didn't find Windows internals particularly interesting until I took on a malware analysis task. It was during this task that I began to appreciate the world of Reverse Engineering on the Windows platform, largely due to the abundance of resources and tools available. Unlike Linux, where everything is open source and accessible through the `unistd.h` header (equivalent to `windows.h` in Linux), Windows introduced me to the concept of so-called 'Undocumented functions.'

In this concise post, my intention is to offer you a quick tip on utilizing undocumented APIs, such as those found in ntdll.dll, and demonstrate how compiler-specific keywords can guide the Microsoft Linker to efficiently resolve these functions. This approach eliminates the need for elaborate techniques to load function addresses. Naturally, there are situations where the runtime resolution approach remains necessary, especially when dynamically loading non-standard libraries.

## Quick recap: What are undocumented functions ?

Undocumented functions are API functions that aren't intended to be accessible for developers based on official vendor documentation, particularly within Microsoft's documentation. However, many of these functions offer significant utility. Take, for instance, NtQueryInformationProcess, a function that furnishes crucial insights about a given process. The challenge isn't confined solely to undocumented functions but also extends to undocumented structures, such as the PEB (Process Environment Block), which exist in a partially documented state. Some of these functions are documented but not made available through standard headers.

To tackle this challenge, a wealth of resources, books, and websites are dedicated exclusively to cataloging and documenting these undocumented functions. Notably, projects like Wine and ReactOS serve as invaluable sources for locating API definitions for these functions. 

When I was learning about Windows programming I learned that I could load these functions by extracting their signatures from these undocumented sources and by employing runtime resolution APIs like `GetProcAddress`, I could procure the function addresses and cast them into function pointers, facilitating the usage of these functions.


```cpp
#include <iostream>
#include <windows.h>
#define NTSTATUS LONG

#define NT_SUCCESS( Status ) ( ( (NTSTATUS) (Status) ) >= 0 )

using pNtAllocateVirtualMemory = NTSTATUS ( * )
(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

int main()
{
	PVOID	Buff		= nullptr;
	SIZE_T	AllocSize	= 0x1000;

	pNtAllocateVirtualMemory NtAllocateVirtualMemory = reinterpret_cast< pNtAllocateVirtualMemory >( GetProcAddress ( LoadLibraryA ( "ntdll.dll" ), "NtAllocateVirtualMemory" ) );
	NTSTATUS status = NtAllocateVirtualMemory ( GetCurrentProcess(), &Buff, 0, &AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (NT_SUCCESS ( status ))
	{
		std::printf ( "Memory Allocated with the NtAllocateVirtualMemory function pointer sucessfully at 0x%p! W & R a byte... \n" );
		*(BYTE*) Buff = 0xF3;

		std::printf ( "Buff[ 0 ] = 0x%x\n", *( BYTE* )Buff);
	}

	std::printf ( "Status %x\n", status );

}
```
In the example above, my goal is to work with NtAllocateVirtualMemory. Even though it's partially documented by Microsoft's MSDN, you won't find it in the regular Windows headers. So, how do you tackle this? Well, it's a trick many folks use: you employ `GetProcAddress` with a handle to the DLL, and you request the `NtAllocateVirtualMemory` address. Then, just cast this address to match the definition of a function pointer.

|![](/assets/images/stop-get-procaddress/func_pointer.png)|
|:--:|
| Fig.1 Working code with GetProcAddress usage |


But how can we simply avoid using the combination of `LoadLibrary` and `GetProcAddress`? Or better yet, how can we use these functions without needing to do tricks to fetch their addresses?

## Quick recap: The compilation process

The C/C++ compilation process is quite straightforward in theory, with these steps:

* Preprocessor
    - Here, the compiler consolidates all your source code and headers into a single point, preparing them for the actual compilation.
* Compilation
    - In this step, your code gets translated into Assembly and is poised for conversion into machine code.
* Assembler:
    - After compilation, your code is transformed into assembly/binary format and bundled in an object code format (`.obj` or `.o`).
* ***Linker***:
    - The object file now incorporates all the functions you used, integrating them into the final executable. This ensures a fully functioning executable with resolved external functions/libraries.


To simplify the process of dealing with undocumented functions, we can make a small adjustment during the Linking step. When this step is reached, we can direct the Linker to use the actual address of NtAllocateVirtualMemory. This can be easily accomplished using compiler-specific keywords that we insert into our code!


## Just use the `#pragma` and `__declspec` keywords


You can make your life easier by employing the [#pragma](https://learn.microsoft.com/en-us/cpp/preprocessor/comment-c-cpp?view=msvc-170#lib) and [__declspec](https://learn.microsoft.com/en-us/cpp/cpp/dllexport-dllimport?view=msvc-170#remarks) keywords. These compiler-specific keywords tools let you instruct the MSVC compiler to find the `NtAllocateVirtualMemory` inside the static library `ntdll.lib`, provided my Microsoft. 

```cpp
#pragma comment(lib, "ntdll.lib")

// ...

extern "C" __declspec( dllimport ) NTSTATUS NtAllocateVirtualMemory (
	HANDLE    ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);
// ..
```

Now there is no need to use the `GetProcAddress`! 

```cpp
PVOID	Buff = nullptr;
SIZE_T	AllocSize = 0x1000;

NTSTATUS status = NtAllocateVirtualMemory ( GetCurrentProcess (), &Buff, 0, &AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

if (NT_SUCCESS ( status ))
{
    std::puts ( "Memory Allocated sucessfully at 0x%p! W & R a byte... \n" );
    *(BYTE*)Buff = 0xF3;

    std::printf ( "Buff[ 0 ] = 0x%x\n", *(BYTE*)Buff );
}

std::printf ( "Status %x\n", status );
```


|![](/assets/images/stop-get-procaddress/using_linker.png)|
|:--:|
|Fig.2 Using Linker keywords |

By using these keywords, you're essentially telling the Microsoft Linker to focus on ntdll.lib while building your project. The `__declspec( dllimport )` keyword is optional, but it's basically telling the compiler that this function definition can be found in the [IAT](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-address-table), is like waving a flag, announcing that this function definition originates from another library, not your source code. 

Since these functions stem from C, rather than C++, remember to use the `extern "C"` keyword to disable the [name mangling](https://en.wikipedia.org/wiki/Name_mangling), that way the function symbol name will match exactly to the one defined in the `ntdll.lib`. Here's a tip: if you're dealing with multiple function definitions, you can gather them all in one neat block using brackets.

```cpp
extern "C"
{
	// Your definitions
}
```


***Is worth to remember that the above approach only works if the function of insterest is exported by the library(`.lib`) file that you want to use!***

## Does this works for kernel Drivers programming ?

This isn't magic; it's simply how linkers operate. The same concept holds true for kernel mode programming! If you're aiming to utilize undocumented functions in your driver, you can apply the same approach:

```cpp
extern "C" __declspec( dllimport ) NTSTATUS NTAPI ZwQuerySystemInformation (
    ULONG SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength 
);
```

The only difference here is that, since you're already working on a kernel driver, you will be using the `ntoskrnl.exe` executable as your main library. Therefore, there's no need to employ the `#pragma` keyword in this context! Also, if you are not using `C++` to code your driver you can remove the `extern "C"` as well.

## Conclusion

Well, that was a simple tip post that I found very useful. I've seen a lot of people not knowing this and using LoadLibrary (or any other) + GetProcAddress all the time. There are a lot of interesting features in these keywords that are worth taking a look at.


Thanks!

--------

08/16/2023 - Edit
	- Fix some concepts related to the compiler-specific keywords and the linking process, thanks [@cxiao](https://github.com/cxiao) to let me know about it.
