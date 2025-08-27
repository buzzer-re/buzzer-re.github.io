---
title: "ELF injection on the PlayStation 5"
date: 2025-08-16 00:00:00 -0300

categories: [Console Hacking]
tags: [Reverse engineering, PS5, Programming, FreeBSD]
---

ELF injection is a crucial task for creating more complex homebrews and assisting with debugging inside consoles, especially if you want to extend application capabilities like the UI or even perform internal mods on your favorite games.

There are a few protections and permission restrictions that prevent simple tasks, such as requesting executable memory pages in user mode (and in kernel mode too, but we’ll leave that for another post), using syscalls like `mmap`. The main reason for this is to prevent multistage shellcode execution, particularly after a ROP chain.

In this post, we'll dive into all the publicly available methods to request executable memory in user mode, how an injection would work, and especially how to instrument the target process to essentially do everything for us. I’ll be using the [9S](https://github.com/buzzer-re/NineS/) project as a showcase, since it’s the result of my research on the topic.

This is a begin of a series of articles that I plan to release over the time, they reflect my research into consoles in general, I plan to do publications based on my public researchs or notes.

***Disclaimer: Console hacking is sometimes a gray area. As everyone knows, many people pursue it for piracy or to obtain private code from the vendor. I will never share any information that isn’t already public or known by the vendors, so do not expect to find zero-days or any kind of data subject to DMCA takedowns. I also do not take responsibility for any actions taken using my research—it is always intended for educational purposes and knowledge sharing only.***

---

## PlayStation 5 Overall Security

Unlike its predecessor, the PS4, the PS5 has implemented several new protection measures that make certain tasks more difficult. In particular, the hypervisor prevents many types of modifications to the console firmware by proactively enforcing memory integrity and restricting access to low-level system features. This makes kernel-level exploitation and firmware patching significantly harder, even after achieving code execution in user space.

The hypervisor implement a feature called "XOM"(eXecute-Only-Memory), in short terms, it avoids that the `.text` can be read or written and can only be executed. Not only that, some techniques that envolve clear the `WP` bit from the `CR0` register are also useless, since modifiying such bits does generate an `vmexit` in the HV, that will endup by crashing the console for security (only the WP bit is protect, you can write in the others).

Another feature is the `SMEP`, on the `CR4`, which protects against execution of usermode pages in kernel mode. Modification/disable on this one also generate an `vmexit` in the HV.

With this mechanisms, the PS5 also don't allocated RWX in usermode from the `mmap` syscall. Which means that even if you could ROP in usermode, you are unable to execute any other thing. 

This security features will be detailed in future articles, but this already gives you an idea of the overall difficult of performing firmware level modifications that may allow the requesting of rwx memory in usermode or to modify any kind of process creation variables (patching the `exec` or `mmap`)

## Current exploit and primitives

By time of the writing, there are currently at least 3 valid usermode entrypoint and 3 public kernel exploits. All of them were reported by different researchers into the PlayStation [HackerOne]() profile. The last possible exploitable PS5 firmware is the `10.01`.

All exploits provides a RW primitives into the kernel, and that is enough to avoid all the security mechanisms that may avoid injection.

## Data-only access and power

Many researchers from the PS5 console hacking scene have helped to find many offsets inside the `.data` section of the kernel, some assisted by decrypted firmware and others just using patterns into it. The .data section of the kernel is in fact unprotected by the HV for perfomance reasons. Since the PlayStation is mainly based on FreeBSD, it's "easy" to figure out what one must do first if it want manipula some process, find the FreeBSD's [proc](https://github.com/freebsd/freebsd-src/blob/676d64ee8327851063d92d0dd6a4ceee6b3a25e6/sys/sys/proc.h#L652) structure.


# Jailbreaking the injector process

To perform ELF injection, one has to at least have power over a process to be able to manipulate it's state to create new threads inside it and to read and write into it's memory (similar on how Windows's injectors works). To achieve that, the `injector` tool must have the necessary permissions to manipulate. A process that is often called `Jailbreak`, since the processes are `jailed` into specific constraints and permissions.

To perform that, I took advantaged of the amazing [SDK](https://github.com/ps5-payload-dev/sdk) currently available, that supports dynamic linking and wrappers to interact with the kernel's read and write primitives.

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

It's worth notice that will such wrappers, it's easy to list all the current processes running in the system and it's PIDs, as a matter of example here's the code that does that (also in the same file):

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
|List of current running processes name, pid and the `proc` entry in the kernel|

## Elevanting process privileges

To elevete the process privileges on the system, is done the same as on the FreeBSD, we set the `cr_uid` as `0` (root) and all other fields related to the current user level/ID as well. There's another caveat, specifically from the PS5 that is the AuthID's, which are a permissions system specifically for the PlayStation that manages special capabilities, such as use debug syscalls such as the `ptrace` and the `mdbg` (more about this later), this also need to be set.

```c

uint8_t* jailbreak_process(pid_t pid)
{
    uint8_t* backup_ucred = malloc(UCRED_SIZE);

    if (!backup_ucred)
    {
        return NULL;
    }

    uintptr_t ucred = kernel_get_proc_ucred(pid);
    //
    // Backup it
    //
    kernel_copyout(ucred, backup_ucred, UCRED_SIZE);

    uint32_t uid_store = 0;
    uint32_t ngroups_store = 0;
    int64_t caps_store = -1;
    uint8_t attr_store[] = {0x80, 0, 0, 0, 0, 0, 0, 0};

    kernel_copyin(&uid_store, ucred + 0x04, 0x4);
    kernel_copyin(&uid_store, ucred + 0x08, 0x4);
    kernel_copyin(&uid_store, ucred + 0x0C, 0x4);
    kernel_copyin(&ngroups_store, ucred + 0x0C, 0x4);
    kernel_copyin(&uid_store, ucred + 0x14, 0x4);


    // Escalate sony privileges
    // kernel_copyin(&authid_store, ucred + 0x58, 0x8);	 // cr_sceAuthID
    kernel_copyin(&caps_store, ucred + 0x60, 0x8);		 // cr_sceCaps[0]
    kernel_copyin(&caps_store, ucred + 0x68, 0x8);		 // cr_sceCaps[1]
    kernel_copyin(attr_store, ucred + 0x83, 0x1);		 // cr_sceAttr[0]

    return backup_ucred;
}
```

Using the Kernel RW primitives, and the `proc` offset, we can easily extract this specific structure from the PS5's kernel and patch it, since it's mapped into a RW segment (Writing into R-only segment is also possible with DMA/MMMIO, but this is a topic for another article). 

With this, the process already userland `root` capabilities, we can even say that the process is `jailbroken`.

# Request usermode executable memory



## FreeBSD's vmmap data structure overview

# Example: Injecting an ELF in the UI

# Conclusion


# References 
