---
title: "A peaceful unpacking, as it should be"
date: 2023-02-13 01:21:00 -0300

categories: [Reverse-Engineering]
tags: [Reverse Engineering, Malware Research]
---
<style>
body {
    text-align: justify;
}
</style>

Wow, it's been more than two years since my last blog post. Time flies! But now, in 2023, I am eager to start filling this blog with cool and useful content, and I hope to maintain it for a long time.

As a welcome back post, I want to share an unpacking of a random sample of the [Redline](https://bazaar.abuse.ch/sample/4daa4b6dfe81b31c09d7d3019eef4d84c071962069fd9c6603e810f88182b80c/) stealer that I found inside Malware Bazaar. The purpose of this post is not to analyze the malware, but rather to dive into the process of manual unpacking and extract deep information about the packer itself.

***While writing this post, I discovered that this is an updated version of the packer that was described by [Fumik0](https://fumik0.com/2021/04/24/anatomy-of-a-simple-and-popular-packer/), in 2021. Although there have been some minor changes to some of its components, I will still use this sample to demonstrate the unpacking process.***

# Spliting the multi-stage loader 

This sample loads its final payload in a multi-stage procedure, which means that there are several steps involved before the actual malware is executed.

## The bad, the good and the ugly unpack formula

Most of the unpacking is done by monitoring memory allocations, breaking at `VirtualAlloc` or `LocalAlloc`, and verifying any memory protection modifications with `VirtualProtect` and so on. However, for the purpose of this analysis, I want to focus on a more precise approach by examining the unpacking code itself.

This means that we first need to reverse the binary statically and determine exactly where we should look. In most cases, you will find a shellcode for analysis. You can identify it by following the code flow until you encounter an indirect jump, a function pointer call in the decompiler view, or something like `jump rax` or `call rax` in the disassembler.


So, our steps for a successful unpacking will be as follows:

1. Locate where the shellcode will be executed.
2. Dump the raw shellcode.
3. Reconstruct the code inside IDA, define struct types, and understand what the code does.
4. Repeat the previous step for each stage of the unpacking process.
5. Fully recover the final binary.

![](/assets/images/unpacking_redline/ed.gif)

With that in mind, let's get started!

## Finding where to stop


|![](/assets/images/unpacking_redline/mainstage1.png)|
|:--:|
| Fig.1 Dead code and dummy code to distract analysis |

This sample employs a lot of junk and unused functions. At first glance in (1), we can see that we are looking at functions that have no use at all. It's common for malware to use obfuscators that insert dummy code flows and function calls.

Also, note that in (2), some pointers are filled with data that is responsible for:

- uBytes: the amount of bytes needed to allocate the shellcode memory
- suspicious: the shellcode information struct, which we will talk about later.

The juicy part is at sub_403340 (`executeHiddenCode`). Let's dive in and search for any function pointer calls.


### Function pointers 

|![](/assets/images/unpacking_redline/first_function_ptr_call.png)|
|:--:|
| Fig.2 Function pointer call at the end |

At the end of the function, it's possible to see a call to a function pointer `SomeHiddenFunction` (`dword_4B6B98`). As it turns out, this memory region is allocated at runtime, and it's fairly easy to find where using the xrefs:


|![](/assets/images/unpacking_redline/someHiddenFunctionAssign.png)|
|:--:|
| Fig.3 shows the memory assignment on the suspicious function pointer. |


Looking at the references to this memory area, it's pretty clear that we should at least look at the only place where there is an assignment to this memory area: `mov SomeHiddenFunction, eax`. From there, it's possible to follow the code flow to understand how this function is built.

|![](/assets/images/unpacking_redline/functionLocalAlloc.png)|
|:--:|
| Fig.4 Function memory allocation. |


Indeed, the function is being allocated at runtime by using the LocalAlloc function. By looking at the xrefs to this allocation function, it's possible to identify that the `executeHiddenFunction` is responsible for calling it.


Later on, the memory area permissions are changed dynamically to allow code execution using the `VirtualProtect` function:

|![](/assets/images/unpacking_redline/virtualprotect.png)|
|:--:|
| Fig.5 Dynamic invocation of VirtualProtect to change memory permissions for shellcode execution |

### Shellcode structure

Do you recall the suspicious variable mentioned earlier? It's actually used as a trick to hide the real encrypted shellcode offset. The trick involves pointing to an invalid memory area and then adding a fixed value of 732475 to it, which ultimately points to the real shellcode blob array address.

|![](/assets/images/unpacking_redline/partOfMem.png)| ![](/assets/images/unpacking_redline/copyingShellcode.png)|
|:--:||:--:|
|Fig.6 Address pointed by the `suspicious` pointer|Fig.7 Address fixed and copying shellcode blob|


In other words, the actual address of the shellcode starts at `0x35FAD5 + 732475 = 0x412810`.

|![](/assets/images/unpacking_redline/shellcodeBlob.png)|
|:--:|
|Fig.8 Shellcode encrypted blob start|

In my first analysis, I did not pay much attention to the encryption scheme used in this code, as I was able to easily dump the shellcode inside x64dbg by breaking at the `SomeHiddenFunction` call. However, after reading the article by [Fumik0](https://fumik0.com/2021/04/24/anatomy-of-a-simple-and-popular-packer/) which analyzes a similar packer, I realized that the encryption scheme used here is the same as in the other packer: the Tiny Encryption Algorithm [TEA](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) (Tiny Encryption Algorithm).

TEA is a symmetric key block cipher with a block size of 64 bits, which was designed to be simple and easy to implement. It uses a 128-bit key to encrypt data in 64-bit blocks, and the same key is used for decryption

I'm not a cryptography expert so I can't dive to much on this part, but here is where the decryption really happens:


|![](/assets/images/unpacking_redline/DecryptWrapper.png)|
|:--:|
|Fig.9 Decrypt prepare and wrapper|



Due to the large amount of junk code and dummy function calls in the binary, I've highlighted only the real decryption code. With the decryption key properly set, the algorithm is able to decrypt the shellcode and execute it in memory.

|![](/assets/images/unpacking_redline/tie_algo.png)|
|:--:|
|Fig.10 TEA algorithm core|



### Dumping the first shellcode


As we have a good understand of the first shellcode stage of this loader, we can already dump it using x64dbg.

|![](/assets/images/unpacking_redline/saving_shellcode.png)|
|:--:|
|Fig.10 Dumping the first shellcode stage|


After triggering the breakpoint at call eax in someHiddenFunction(), we can navigate to where eax points on the dump tab and save the contents to a file. This will allow us to dump the first stage shellcode.

![](/assets/images/unpacking_redline/manual_unpack_meme.jpg)

# Shellcode Analysis