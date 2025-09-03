---
title: "Usermode ELF injection on the PlayStation 5"
date: 2025-09-03 00:00:00 -0300

categories: [Console Hacking]
tags: [Reverse engineering, PS5, Programming, FreeBSD]
---

ELF injection is crucial for developing complex homebrew applications, helping with debugging and instrumentation during security research, and specially for extending application capabilities, such as enhancing the UI or creating internal mods for your favorite games.

There are a few protections and permission restrictions that prevent simple tasks, such as requesting executable memory pages in user mode (and in kernel mode too, but we’ll leave that for another post), using syscalls like `mmap`. The main reason for this is to prevent multistage shellcode execution, particularly after a ROP chain but directly after any kind of injection.

In this post, we'll dive into the available methods to request executable memory in user mode, how an injection would work, and especially how to instrument the target process to essentially do everything for us. I’ll be using the [9S](https://github.com/buzzer-re/NineS/) project as a showcase, since it’s the result of my research on the topic.

And yes, the project name is inspired on the [YoRHa No.9 Type S](https://nier.fandom.com/wiki/YoRHa_No.9_Type_S) from Nier Automata, for the who played the game I'm sure you will understand the inspiration.

Also, inspired by my friend [Kewou](https://github.com/keowu) [writings](https://keowu.re/posts/Rewriting-completely-the-GameSpy-support-from-2000-to-2004-using-Reverse-Engineering-on-EA-and-Bungie-Games), I'll be leaving a [music](www.youtube.com/watch?v=ojtOXJlc6uYv) to listen while read the article. 

---


## PlayStation 5 Overall Security

Unlike its predecessor, the PS4, the PS5 has implemented several new protection measures that make certain tasks more difficult. In particular, the hypervisor prevents many types of modifications to the console firmware by proactively enforcing memory integrity and restricting access to low-level system features. This makes kernel-level exploitation and firmware patching significantly harder, even after achieving code execution in kernel space.

The hypervisor implement a feature called "XOM"(eXecute-Only-Memory), in short terms, it avoids that the `.text` can be read or written and can only be executed. Not only that, some techniques that envolve clear the `WP` bit from the `CR0` register are also useless, since modifiying such bits does generate an `vmexit` in the HV, that will endup by crashing the console for security (only the WP bit is protect, you can write in the others).

Another feature is the `SMEP`, on the `CR4`, which protects against execution of usermode pages in kernel mode. Modification/disable on this one also generate an `vmexit` in the HV.

Within this mechanisms, the PS5 also enforces the allocation RW pages in usermode using syscalls like the `mmap` syscall. Which means that even if you could ROP in usermode, you are unable (in theory) to request new RWX memory pages to execute any other thing. 

This security features will be detailed in future articles, but this already gives you an idea of the overall difficult of performing firmware level modifications that may allow the requesting of rwx memory in usermode or to modify any kind of process creation variables (patching the `exec` or `mmap`)

## Current exploit and primitives

By time of the writing, there are currently at least 3 valid usermode entrypoint and 3 public kernel exploits. All of them were reported by different researchers into the PlayStation [HackerOne](https://hackerone.com/playstation/hacktivity) profile. The last possible exploitable PS5 firmware is the `10.01`.

All exploits provides a RW primitives into the kernel, and that is enough to avoid all the security mechanisms that may avoid injection.


To write code into the PS5, I took used the amazing [SDK](https://github.com/ps5-payload-dev/sdk) currently available, that supports dynamic linking and wrappers to interact with the kernel's read and write primitives.

## Data-only access

Many researchers from the PS5 console hacking scene have helped to find many offsets inside the `.data` section of the kernel, some assisted by decrypted firmware and others just using patterns into it. The .data section of the kernel is in fact unprotected by the HV for perfomance reasons. Since the PlayStation is mainly based on FreeBSD, it's "easy" to figure out what one must do first if it want manipulate some process, find the FreeBSD's [proc](https://github.com/freebsd/freebsd-src/blob/676d64ee8327851063d92d0dd6a4ceee6b3a25e6/sys/sys/proc.h#L652) structure.


# Elevating the injector process

To perform ELF injection, one has to at least have power over a process to be able to manipulate it's state to create new threads inside it and to read and write into it's memory (similar on how Windows's injectors works). To achieve that, the `injector` tool must have the necessary permissions to at least call syscalls such as `ptrace`, as it's crucial for instrumentation.

To do this, we need to manipulate the `proc` structure in FreeBSD, which contains many attributes of our process.

## Manipulating the FreeBSD's ***proc*** structure


The FreeBSD's [proc](https://github.com/freebsd/freebsd-src/blob/676d64ee8327851063d92d0dd6a4ceee6b3a25e6/sys/sys/proc.h#L652) structure is a linked list containing all current processes, it contains basic information such the PID and UID, also contains some Authentication ID's, find the offset is trivial, once one has access to it can use the Kernel RW primitives to read the `proc` structure from the kernel `.data`.


```c
struct proc* find_proc_by_name(const char* proc_name)
{

    uint64_t next = 0;
    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t)); // 1
    struct proc* proc = (struct proc*) malloc(sizeof(struct proc));
    do
    {
        kernel_copyout(next, (void*) proc, sizeof(struct proc)); // 2

        if (!strcmp(proc->p_comm, proc_name))
            return proc;

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
    return NULL;
}
```

The example above was extract by a wrapper that I've [wrote](https://github.com/buzzer-re/NineS/blob/main/src/proc.c) to interact with such kernel data structures, it will use the `kernel_copyout` function that encapuled the Read primitive from the kernel exploit, to extract the first entry of the `proc` linked list (1), therefore to read every entry it will need to also perform another Kernel read (2). When a give entry is found by some process name, it will return the copied `proc` structure.

It's worth notice that with such wrappers, it's easy to list all the current processes running in the system and it's PIDs, as a matter of example here's the code that does that (also in the same file):

```c
void list_all_proc_and_pid()
{

    uint64_t next = 0;
    kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t));
    struct proc* proc = (struct proc*) malloc(sizeof(struct proc));

    do
    {
        kernel_copyout(next, (void*) proc, sizeof(struct proc));

        printf("%s - %d\n", proc->p_comm, proc->pid);

        kernel_copyout(next, &next, sizeof(uint64_t));

    } while (next);

    free(proc);
}
```

The code is self explainatory, and it's outputs the following text into the [klog](https://lists.freebsd.org/pipermail/freebsd-questions/2006-October/134233.html):

|![](/assets/images/playstation-5-elf-injection/list_procs.png)|
|:--:|
|List of current running processes name, pid and the `proc` address entry in the kernel|

## Elevating Process Privileges

The PlayStation `proc` structure is basically the same as the FreeBSD, but it does contains specific fields created for the console, such as the Authority ID which is added inside the [ucred](https://web.mit.edu/freebsd/head/sys/sys/ucred.h) structure, which is part of the `struct proc`. This structure contains specific codes that describe a process permission of some resources or capabilities. In order to be able to debug remote process, which means use the `ptrace` and the `mdbg` syscall families (specific from the console), we need to add this permission into our process. 

With R/W primitives the code that does that is pretty simple, and is the following:

```c
//
// Search process entr on the allproc linked list
// acquire the "ucred" structure and elevate it
//
void set_ucred_to_debugger()
{
    struct proc* proc = get_proc_by_pid(getpid());

    if (proc)
    {
        //
        // Parse process ucred
        //
        struct ucred ucred;
        bzero(&ucred, sizeof(struct ucred));
        //
        // Read from kernel
        //
        uintptr_t authid = 0;
        uintptr_t ptrace_authid = PTRACE_AUTHID;
        kernel_copyout((uintptr_t) proc->p_ucred + 0x58, &authid, sizeof(uintptr_t));

        kernel_copyin(&ptrace_authid, (uintptr_t) proc->p_ucred + 0x58, sizeof(uintptr_t));

        free(proc);
    }
}
```

The `authid` is located at offset `0x58` of the `ucred` structure. Using hardcoded offsets is not recommended, but as the kernel is not open source, and we cannot rely on the structure maintaining its layout. Therefore, it is common to maintain a reversed structure on the researcher's side (using tools like IDA or Ghidra) and update the value as needed.

The `PTRACE_AUTHID` value is `0x4800000000010003`. After setting it, the process is permitted to use debug-related syscalls and functions, which will be explored in the following sections.

# Requesting usermode executable memory

Now, if you want to inject something into a process, you have two options: either allocate remote executable memory within the target process or overwrite something inside it. In fact, my injector does both. As I wrote, it's not possible to simply allocate memory pages with `PROT_EXEC|PROT_READ|PROT_WRITE`, but some processes, like browsers that use JIT to run JavaScript code, still need it. 

Knowing this, the PS5 provides wrappers to specifically request JIT memory. These API calls are mostly used by browsers or any process that makes use of it (like the Redis server running in the background for caching). 

In the first version of the injector and the SDK elfldr, it did exactly that. It used to run all the ELF inside JIT memory, which is not ideal because it requires more work to mirror the page.

## FreeBSD's vmmap data structure overview

FreeBSD keeps track of all process memory in a structure named [vm_map](https://man.freebsd.org/cgi/man.cgi?query=vm_map), which is a data structure of allocated pages for a process. It contains an element named `struct vm_map_entry header`, which is the entry point for all the pages. Internally, it uses two possible data structures: a double-linked list to perform linear searches and a [Binary-Search-Tree](https://en.wikipedia.org/wiki/Binary_search_tree).


Each page entry contains the following structure:

```c
struct vm_map_entry {
    struct vm_map_entry *prev;
    struct vm_map_entry *next;
    struct vm_map_entry *left;
    struct vm_map_entry *right;
    vm_offset_t start;
    vm_offset_t end;
    vm_offset_t avail_ssize;
    vm_size_t adj_free;
    vm_size_t max_free;
    union vm_map_object object;
    vm_ooffset_t offset;
    vm_eflags_t eflags;
    /*	Only in	task maps: */
    vm_prot_t protection;
    vm_prot_t max_protection;
    vm_inherit_t inheritance;
    int wired_count;
    vm_pindex_t lastr;
};
```

What matters most is the `vm_prot_t protection`, which holds the current page protection. It can be `PROT_READ`, `PROT_WRITE`, `PROT_EXEC`, or a combination of them. As mentioned before, the kernel enforces only `PROT_READ|PROT_WRITE` as the maximum for requested pages from usermode. 

But with the RW primitives and access to this data structure, one can simply add `PROT_EXEC` to any page they want. I’ve wrapped this idea in my [proc](https://github.com/buzzer-re/playstation_research_utils/blob/863e832606636e978a69f8557f0db782b9acdcc7/ps5_proc_structure/src/proc.c#L76) wrapper, which can be used to modify any usermode page protection bit. This was also implemented in the [SDK](https://github.com/ps5-payload-dev/sdk/blob/c028c113330c7da62bf50890ea085e2ef6760a2c/crt/kernel.c#L1201). Initially, the SDK only used the double-linked list fields to perform a simple linear search, which was sufficient most of the time. My [contribution](https://github.com/ps5-payload-dev/sdk/commit/45ba1ca929dcfeae46b84a053d0b31725107a78b) was to add the Binary Search Tree algorithm with the correct offsets to increase the page search/patch speed. Nevertheless, with all this shared, the result is that we are now able to:

- Jailbreak the process to give it debug capabilities
- Request usermode executable memory

The missing piece is how to combine both of these to map an ELF inside another process’s userspace. This is achieved by using the [elfldr](https://github.com/ps5-payload-dev/elfldr).

# Mapping an ELF in the remote process

Unlike Windows, where API calls like`VirtualAllocEx` (allocate memory inside another process) exist, this is not true in the Unix world. You don’t have access to such functions to do that you need to instrument the target process to ask it nicely to do it. 

Behind the scenes, the [elfldr](https://github.com/ps5-payload-dev/elfldr) uses a ptrace wrapper that can call remote functions. Basically, if you can pause the target process thread, save its state, specifically craft the RIP and the necessary arguments to another address, and resume it, this will result in a call to any remote function. You can check its implementation [here](https://github.com/ps5-payload-dev/elfldr/blob/fe0b8bb337bd243ffd2ca073d702902cd70fb7e4/pt.c#L213). 

I’ve modified the elfldr source code to only map the ELF inside the process space (nothing more), giving me the opportunity to call it inside another thread. What my injector does is the following:

* Use a slightly modified version of the elfldr to map the ELF correctly within the target memory space
* Write a small shellcode in the target process to call the pthread_create function, issue an int3 to notify the injector
* Detach from the process
* The ELF is now running in a different thread

All this can be checked [here](https://github.com/buzzer-re/NineS/blob/e8eaaa06ebc62e3f1f6ac642a0fc85417439887b/src/injector.c#L75), but the important piece of code is:

```c
intptr_t entry = elfldr_load(proc->pid, (uint8_t*) elf);

...

intptr_t args = elfldr_payload_args(proc->pid);
printf("[+] ELF entrypoint: %#02lx [+]\n[+] Payload Args: %#02lx [+]\n", entry, args);
```


`entry` is, as the name suggests, the entrypoint of the executable. It points to the SDK’s CRT, which needs the `payload_args_t` structure to work correctly. This structure contains important information provided by the exploit, such as the Kernel R/W primitives and some addresses. This is used by its dynamic linker to resolve necessary functions and apply necessary process permission patches to work properly. The injected code that bootstraps the ELF is simple; here’s its core:

```c
int __attribute__((section(".stager_shellcode$1")))  stager(SCEFunctions* functions)
{
    pthread_t thread;
    functions->pthread_create_ptr(&thread, 0, (void *(*)(void *)) functions->elf_main, functions->payload_args);

    asm("int3");

    return 0;
}
```

t’s very similar to what you would expect in environments like Windows; the main difference is the existence of the `asm("int3")`, which, as mentioned before, serves to notify the injector that it’s time to detach (it also significantly speeds up execution). With all that, the ELF is now successfully running on any target process.


# Example: Injecting an ELF in the UI

As an example, the following hello world will be executed inside the `SceShellUI` process, which is the entire PS5’s UI process.

```c
#include <stdio.h>
#include <unistd.h>
#include <ps5/klog.h>


int main() 
{
  klog_printf("Hello from PID %d\n", getpid());
  return 0;
}

```
I’ve created [9S](https://github.com/buzzer-re/NineS) as a server running on port 9033. It expects the following struct as an input argument:

```c
typedef struct __injector_data_t
{
    char proc_name[MAX_PROC_NAME];
    Elf64_Ehdr elf_header;
} injector_data_t;
```

To make life easier, I created a simple Python [script](https://github.com/buzzer-re/NineS/blob/main/send_injection_elf.py) to send any ELF file to it. It can be used as:


> python3 ./send_injection_elf.py SceShellUI hello_world.elf IP

First, let’s check the SceShellUI PID to make sure the injection works:

|![](/assets/images/playstation-5-elf-injection/pid_check.png)|
|:--:|
|PID check|

Now, let’s inject the ELF and see if it’s really running inside the target process:

|![](/assets/images/playstation-5-elf-injection/inject_example.png)|
|ELF injection successfully|


# Conclusion


This concludes this article. I wrote this injector a while ago and didn’t plan to write about it, but recently, after talking with a few friends about knowledge sharing, I realized that this type of material is essential. It’s not entirely specific to the PS5 and has a lot to do with OS internals, such as those in FreeBSD. 

Also, I’ve been using this tool extensively this past year, especially for debugging, experimentation, and reverse engineering projects. If I’m using it that much, why can’t someone else use it too?


# References 

There are many references I’ve used, I may miss some, but here’s all the material I used:

* [FreeBSD source code](https://github.com/freebsd/freebsd-src)
* [elfldr](https://github.com/ps5-payload-dev/elfldr)
* [SDK](https://github.com/ps5-payload-dev/sdk)
* [Mira](https://github.com/OpenOrbis/mira-project)
* [gdbsrv](https://github.com/ps5-payload-dev/gdbsrv)

Also, after this tool’s publication, a friend of mine wrote the entire ptrace instrumentation tool, inspired on the originally written for FreeBSD/PS5, for a cool Linux project named [plinux](https://github.com/rem0obb/plinux).