---
layout: post
title: "Linux Kernel: Weaponizing an AAW & Heap Ovf (Blunder Driver Challenge)"
tags: 
 - Linux-Kernel
---

This blog will be about exploiting a Linux Kernel Driver by chaining a **Heap Overflow** bug with a 'sandboxed' **Arbitrary Address Write (AAW)** for **Local Priviledge Escalation** by overwriting **core_pattern** with most mitigations enabled. 

It is required that the reader is familiar with basic **Linux Kernel Exploitation** and the structure of the **Kernel Heap** but this is not required since I will try to expound on these topics to the best of my knowledge. 

### Vulnerable Driver 

The vulnerable driver named `blunder` was part of the exploitation challenges provided by [Blue Frost Security](https://labs.bluefrostsecurity.de) _(offensive+con organizers)_. The source code and the `makefile` were provided [here](https://labs.bluefrostsecurity.de/blog.html/2022/10/25/bfs-ekoparty-2022-exploitation-challenges/) for compilation. 

From the provided source code, the driver is somewhat similar to Android's `binder`/ `Linux System V message queue` implementing an **Inter Process Communication** mechanism for sending and receiving messages between processes. When the driver is compiled and loaded `insmod` into the Kernel, this will create an interface at `/dev/blunder` that can be used to communicate with the driver.

The driver was compiled on Linux Version `5.4.0` for this first part of the article, with the following mitigations enabled:
- [x] `SLUB_FREELIST_RANDOMIZATION`
- [x] `CONFIG_CHECKPOINT_RESTORE`
- [x] `USER_HARDENED_COPY`
- [x] `SMEP`, `SMAP`, `KPTI`, `FG-KASLR` 

The kernel config and the compiled `bzImage` that were used to develop the final exploit, can be found [here](https://github.com/mutur4) 

### Vulnerability Analysis

Since the source code of the driver is already provided, we can do some source-code review  with the aim of understanding how the driver works and to check for any present vulnerabilities *(mainly where the kernel processes userland data)*. 

In summary, when a process sends or receives a message, the following set of actions are performed by the process:

 - Opening the device driver `/dev/blunder` to initialized specific objects.
 - Creating a new mapping in the `virtual Address Space` of the process to send and receive messages. 
 - The message(s) are sent via ioctl `IOCTL_BLUNDER_SEND_MSG` and received via `IOCTL_BLUNDER_RECV_MSG`.

The following file operations play a major role in implemented the above actions:
![blunder_fops](https://i.imgur.com/TBpJ1Dd.png)

#### *blunder_open*

This function is called when a process first opens the device driver performing the following:
 1. A `blunder_proc` object is allocated on the heap and its values are initialized. This object is then stored in the driver's `file->private_data` for reference.
 2. The driver limits only a single process to trigger the call to `blunder_open`.

The following is the code snippet that performs the above actions:
```c
static int blunder_open(struct inode *inode, struct file *file){
	...
	proc = (struct blunder_proc *) kzalloc(sizeof(*proc), GFP_KERNEL);
	...
	file->private_data = (void *) proc;
	
}
```
The `blunder_proc` object is an important object that stores useful information about a process sending and receiving messages. The following are the members of this structure.

```c
struct blunder_proc {
	struct kref refcount;
	spinlock_t lock;
	int pid;
	int dead;
	struct rb_node rb_node;
	struct blunder_alloc alloc;
	struct list_head messages;
}
```


#### *blunder_mmap*

The function is triggered when a process calls `mmap` when mapping a new Virtual Address Space. The driver implements its own `mmap` implementation that returns a physical mapping shared between the kernel and userland. When the function is called, the following actions are performed:
 1. The allocated object `blunder_proc` is retrieved from `filp->private_data`.
 2. The map options passed via `mmap` are checked to determine if a process requested a mapping that is larger than the maximum and the `vma` flags are also checked to make sure that the requested mapping/page is not writable. 
 3. An object is allocated on the kernel heap based on the size passed via `mmap`. This address is stored at `proc->alloc.mapping` that is of the type `struct blunder_alloc`. This chunk is also type-cast into a `blunder_buffer` object where messages are stored. 
 4. The above chunk's (Kernel Virtual Address) is translated to a physical address and this physical address is mapped to a user-space virtual address that is returned to `mmap`.

The following code snippet perform the above actions:

```c
static int blunder_mmap(struct file *filp, struct vm_area_struct *vma){
	struct blunder_proc *proc = (struct blunder_proc *) filp->private_data;
	...
	if(sz > BLUNDER_MAX_MAP_SIZE || vma->vm_flags & VM_WRITE){
		exit(1);
	}
	...
	//a chunk is allocated from the heap via kmalloc
	void *buf = kmalloc(sz, GFP_KERNEL);
	...
	proc->alloc.mapping  = buf;
 	...
	//typecast the chunk to a blunder_buffer object
	struct blunder_buffer *first_buffer = (struct blunder_buffer *) proc->alloc.mapping;
	first_buffer -> buffer_size = proc->alloc.mapping - sizeof(*first_buf);
	
	//The virtual address is mapped to a physical address
	pfn = virt_phys(proc->alloc.mapping) >>  PAGE_SHIFT;
	
	//The physical address is mapped to a userland address and returned 
	int ret = remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
	...
	return ret;
}
```
The `blunder_buffer` object which is the above mapping shared by both the kernel and userland and that stores a process's IPC message(s) is as follows:

```c
struct blunder_buffer {
	struct list_head buffers_node;
	atomic_t free;
	size_t buffer_size;
	size_t data_size;
	size_t offsets_size;
	unsigned char data[0];
}
```
From the above code snippet in `blunder_mmap`, the address that will be returned to `mmap` and the address allocated on the Linux Kernel heap point to the same physical address, this therefore means that any change that is made on one side will be visible on the other (same mapping is shared). This seems a little secure since a userland process is not able to write to this mapping right? 

![blunder_mmap](https://i.imgur.com/3pFNFTr.png)

From a hint provided by **BFS** [here](https://x.com/bluefrostsec/status/1586740929041506305). There is a flag called the `VM_MAYWRITE` flag that is a part of `vma->vm-flags` that was not checked. This flag is set by default if a device file is opened with write permissions.

```c
int fds = open("/dev/blunder", O_RDWR); //The driver is opened for reading and writing
```  
The driver not checking for this flag during its `mmap` implementation means that after the mapping, the memory permission(s) can later be changed via `mprotect` to make this region writable.  

```c
mprotect(addr, size, PROT_READ|PROT_WRITE); //simple code snippet for changing memory permmissions
``` 
This leads to a sandboxed `AAW` in the shared mapping; by 'sandboxed' I mean the bug can only be used within the page size'd chunk range returned by `kmalloc` and shared between user and kernel land. 
![wtf](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExeTYweTJtZnJsbmgyenFmZGtnM3c4b2RrZ2cwaTNqcGd0eHY0MGd2diZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/fnuSiwXMTV3zmYDf6k/giphy.gif)

### Heap Buffer Overflow

*So at this point the driver is vulnerable to an AAW. How can this be leveraged to control execution?*

When a process sends a message for IPC, it uses the allocated mapping `proc->mapping` to store messages of the type `blunder_buffer` and the mapping is split to fit more messages as they're sent until that page-sized block is exhausted. This is evident from the following source code snippet that is called from `blunder_send_msg(struct blunder_proc *proc, struct blunder_user_message *__user arg)`. 

![blunder_alloc_gef_buf](https://i.imgur.com/7RWf3lQ.png)


The `blunder_buffer` objects are tracked via a linked-list and an actual buffer is returned to copy the message from userland if its 'free' and if its size is greater than than provided by the user.

```c
//blunder_alloc_get_buf() function
//This checks if the buffer is 'free' and if its size is greater than that provided by the user
if (atomic_free(&buf->free) && buf->buffer_size >= size)	
```

When a buffer is returned by the above function, userland data is then copied to this location as evident from the following source code snippet. 

![blunder_send_message](https://i.imgur.com/7YJsaCX.png)

The above `copy_from_user` function will copy `N` bytes which is the message size provided by the user. This size is only checked in the `alloc_get_buf` function, therefore, to be able to trigger a heap buffer overflow we need to find a way to modify `blunder_buffer->buffer_size` and this can be easily done as follows using the `AAW` introduced above:

1. Send the first message to trigger split and create a new buffer near the end of the page-sized block.
2. Use the `AAW` to overwrite `blunder_buffer->buffer_size` to a big size.
3. When the above `copy_from_user` is called, this will trigger a heap buffer overflow that should overwrite and corrupt the next object on the heap.

During the allocation of this memory block via `kmalloc`, since the size is passed via `mmap`; this means that this size should be page aligned and the minimum size that can be allocated is `0x1000` bytes. There are also not any usable elastic objects > `0x1000` bytes that can be sprayed on the heap to be corrupted therefore, we are gonna stick to `0x1000` bytes during allocation.

#### *Elastic Objects* 

An elastic kernel object or sometimes referred to as a 'usable' object is an object that contains a length field that can allow an attacker manipulate its value controlling its allocation on the heap.
When the kernel accesses the data from the allocated object, the length field indicates the range of data that the kernel can read or write. 

When exploiting most Linux Kernel Heap vulnerabilities (Heap Overflows or kUAFs) an attacker would for example corrupt these objects to control execution flow *(overwriting function pointers)* or to leak kernel addresses to bypass **KASLR**.

#### *Slab Caches*

There are different memory allocators in the Linux Kernel but the most common is the **slab allocator** that sits ontop of the primary allocator the **buddy allocator**. The internals of these allocators is beyond the scope of this article but a detailed analysis of how these allocators work is provided at [2].


When an object is allocated via the `k*alloc` group of functions, based on the size, this particular object will be allocated in a particular **slab cache**. A slab cache is used to manage slabs that inturn store objects of the same size. A slab is basically a page-sized block that is split into smaller empty blocks where objects are stored.

![slab_cache](https://www.notion.so/image/https%3A%2F%2Fhammertux.github.io%2Fimg%2Fslab-org.png?table=block&id=dbaaf118-ea4a-4fcf-ad84-285685a2e6c0&spaceId=7f8ea3cd-52dd-4634-9cc1-20972d00335f&width=2000&userId=9ca9f9d7-3c98-4ddd-9328-dad0491b62e5&cache=v2)

For example, when a `32` byte object is allocated via `kmalloc(32, GFP_KERNEL)` the allocation will be handled by the `kmalloc-32` cache. This cache contains data-structures that keep track of partial and active slabs __*(full slabs are not tracked not until an object from this slab is free'd)*__, therefore if there is an empty 32-byte sized block inside the active slab, this will be returned to kmalloc. 

The number of slabs in a cache is system specific but a `kmalloc-32` cache's slab is a single page-sized block that is `0x1000` bytes with `0x1000/0x20` or `128` objects. The information about these slab cache's can be found at `/proc/slabinfo`.

In our driver's case, when we allocate a page-sized object, this will endup in the `kmalloc-1k` slab cache. Since we already know how to trigger a heap ovf vulnerability, what `kmalloc-1k` elastic objects can we corrupt for exploitation? [This](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628) article has a curative list of elastic objects and how they can be abused for exploitation.

#### *msg_msg objects*

These are objects used to send and receive messages from a **system V Message Queue** for the purpose of Inter-Process Communication. A process is able to write to the message queue to send a message and another process is able to read from the message queue to receive a message using the `msgsnd` and `msgrcv` system calls respectively. The manpages of these system calls describe their usages in detail.
 
During exploitation, these are `kmalloc-1k` elastic objects that can be corrupted to leak kernel addresses for bypassing`FG-KASLR`. Unfortunately, they don't have any usable function pointers that can be corrupted to control execution. These objects are analysed in more detail [here](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html) and [here](https://syst3mfailure.io/wall-of-perdition/) to understand how their implementations can be useful to an attacker.

 One important thing to note is that to be able to leak address from the heap to bypass `USER_HARDENED_COPY` the kernel should be compiled with the `CONFIG_CHECKPOINT_RESTORE` configuration enabled. 

#### *shm_file_data*

When the above `msg_msg` object's message size is greater than the page size `0x1000` bytes, the message is split and allocated a new chunk via `kmalloc`. When using `msg_msg` objects to leak addresses,we will have to make sure the split message is allocated in the `kmalloc-32` cache near a `shm_file_data` elastic object to leak its struct member addresses.
 
### Heap (Grooming) Fengshui

**Heap Grooming** is art especially when exploiting heap-based vulnerabilities. The aim at this point is to be able to manipulate the slab allocator to allocate a `msg_msg` object right after our `proc->alloc->mapping` in the same slab for us to trigger the heap ovf and corrupt the object.

As mentioned above, a slab cache will keep track of **partial** and **active** slabs where the active slab is the one used to service the next allocation. Since we do not have control of these slabs, we will therefore spray `msg_msg` objects with the aim of getting an alloction near our `proc->alloc->mapping` in any of the partial slabs or if we are lucky enough, we could also get allocated a new empty slab that will only contain our victim and sprayed target objects. 

The same can also be done in `kmalloc-32` by spraying `shm_file_data` elastic objects before the allocation of `msg_msg` objects with the aim of getting a split `msg_msg` object called a `msg_seg` allocated right before an `shm_file_data`  object.

The following shows the source code snippet for spraying these elastic objects on the heap before triggering the allocation of our driver's `proc->alloc->mapping` via `mmap`.

![elastic_objects_spray](https://i.imgur.com/2pUzIiu.png) 

> **NOTE**: I like to somewhat wrap my vulnerable objects between elastic objects during sprays, idk but it somehow increases the chances of having an elastic object allocated right after the vulnerable/victim object. 

### Weaponization

#### *__Leaking addresses__*
When the allocation of the elastic target and victim objects align, the `AAW` can be used to modify the split `blunder_buffer` object's buffer size, to introduce a heap overflow that can be used to overwrite `msg_msg->m_ts` value to a bigger value that should allow us read passed its (split) message segment in the `kmalloc-32` cache to leak kernel addresses.


![attack_flow](https://i.imgur.com/5blcq5J.png)

The leaked ddress is the address of `INIT_IPC_NS` that resides in the kernel data area *(not affected by FG-KASLR)*, this can then be used to calculate the kernel base address to bypass `KASLR`.

#### *__Controlling Execution flow__*

There are different techniques that can be used when attacking the kernel to control execution and return back to userland as `root`. Since we have an `AAW` and the `blunder_buffer` objects are connected via a doubly linked list, the idea was to overwrite the `*next` pointer with a kernel address that we want to corrupt introducing a **Kernel Arbitrary Address Write**. 

There are many targets for example `modprobe_path`, `cred_struct` or even `core_pattern` the only problem is when the `blunder_buffer` objects are traversed the following checks are done before a write is triggered. 

1. The `blunder_buffer->free` should not be NULL.
2. The `blunder_buffer->buffer_size` should be greater that the user provided data.

This is evident from the following driver's source code snippet:

```c
if (atomic_read(&buf->free) && buf->buffer_size >= size){
	...
	return buf;
}
``` 
This therefore means that we have to typecast our target to a `blunder_buffer` object with the following structure.

```c
struct blunder_buffer{
	struct list_head buffer_nodes;
	atomic_t free; //This is required to write into data
	size_t buffer_size; //This determines the bytes written to data from userland
	size_t data_size;
	size_t offsets_size
	unsigned char data[0]; // The target address should go here 
}
```

From the list of addresses above, the only candidate that satisfied the above requirements was `core_pattern`. The following shows the analysis of this address in memory. 

![image](https://i.imgur.com/qJpMfsO.png) 

#### *overwriting core_pattern*

When a process receives a signal for example a segmentation fault, each of these signals has a current disposition that is used to determine how a function behaves when its delivered a signal. 

Some signals like `SIGSEGV` their default action is to terminate and produce a core dump file. This is a file that contains an image of the process memory at the time of termination.

When a core dump file is produced, the kernel will use the `/sys/proc/kernel/core_pattern` file to determine the format and the path to dump the core file. 

```bash
sudo echo "/tmp/core-file->%e->%s->%u" > /proc/sys/kernel/core_pattern
```
For example when a segmentation fault is trigger in a process and the `ulimit` is set to `unlimited`, a core file will be dumped in the `tmp` folder as follows based on the above `core_pattern` file.

```bash
-rw-------  1 kali kali 303104 Jun 18 04:56 'core-file->exec->11->1000'
```

The `core_pattern` can also be configuerd to run commands via the pipe symbol `|`. For example when the following is the content of the `core_pattern` file, the script at `/tmp/exp` will be executed. 

```bash
echo "|/tmp/exp" > /proc/sys/kernel/core_pattern
``` 
Using the above write primitive, we can write `|/tmp/exp` to the `core_pattern` address with the following as the contents of the `/tmp/exp` file.

```bash
#! /bin/bash

cp /bin/bash /tmp/bash
chmod 4755 /tmp/bash
chown root:root /tmp/bash
```
When a process receives a segmentation fault, instead of generating a core file, it will execute the contents of the `/tmp/exp` file as `root`. This will create a copy of `/tmp/bash` in the temp folder with the `suid` bit set. When this executable is executed `/tmp/bash -p` a shell will be returned with escalated privz to root.

When the final exploit is executed the following is the expected output. There is a `verify_exploit` function the reads the content of `/proc/sys/kernel/core_pattern` to check if the contents were modified as required. I tried to create a child process that crashes with a segmentation fault to dump a core file but for some reason `/tmp/exp` could not be executed. 

> When generating a core file, make sure that `ulimit -c unlimited` is set. 

The following is the result of running the file exploit. 

![file_exploit](https://i.imgur.com/pmVgqjm.png)

The final exploit and all the configuration files used for building the kernel are provided [here](https://github.com/mutur4/Blunder-Kernel-Driver)

### Conclusion 

This article was about exploiting a heap overflow vulnerability to bypasss `FG-KASLR` and using an Arbitrary Address Write to overwrite `core_pattern` for LPE with a less-hardened old kernel used for exploitation. 

The next article will cover the exploitation of these vulnerabilities in a more hardened kernel using the `cross-cache` attack. This is because on modern Kernels most elastic objects are allocated in dedicated caches this is `kmalloc-cg-1k` instead of `kmalloc-1k` making traditional heap-overflow exploitation techniques a bit difficult.

> **NOTE**: The above 'dedicated cache' was actually a feature rather than a mitigation

Until next time adios! `_exit(0)` 

### References

- [1] https://blog.wohin.me/posts/paper-eloise/
- [2] https://sam4k.com/linternals-memory-allocators-0x02/

