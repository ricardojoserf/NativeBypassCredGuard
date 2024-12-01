# NativeBypassCredGuard

NativeBypassCredGuard is a tool designed to bypass Credential Guard by patching wdigest.dll using only NTAPI functions (from ntdll.dll).

It locates the pattern "39 ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00" in the wdigest.dll file on disk (as described in the blog post in References section, this is constant in all Windows versions), calculates the memory addresses and finally patches the variables *g_IsCredGuardEnabled* (to 0) and *g_fParameter_UseLogonCredential* (to 1) within wdigest.dll.

Using only NTAPI functions it is possible to remap the ntdll.dll library to bypass user-mode hooks and security mechanisms, which is an optional feature of the tool. If used, the clean ntdll.dll is obtained from a process created in debug mode, using again NTAPI functions except for kernel32!CreateProcess and kernel32!DebugActiveProcessStop.


The NTAPI functions needed are:

![poc](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/esquema.png)

- NtOpenProcessToken and NtAdjustPrivilegesToken to enable SeDebugPrivilege privilege
- NtCreateFile and NtReadFile to open a handle to the DLL file in disk and read its bytes
- NtGetNextProcess and NtQueryInformationProcess to get a handle to the lsass process
- NtReadVirtualMemory and NtQueryInformationProcess to get wdigest.dll base address
- NtReadVirtualMemory to read the value of the variables 
- NtWriteProcessMemory to write new values to the variables


-------------------

## Usage

```
NativeBypassCredGuard <OPTION> <REMAP-NTDLL>
```

Option (required):
- **check**: Read current values.
- **patch**: Write new values.

Remap ntdll (optional):
- **true**: Remap the ntdll library.
- **false** (or omitted): Do not remap the ntdll library.


-------------------

## Examples

Read values (**without** ntdll remapping):

```
NativeBypassCredGuard.exe check
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/Screenshot_1.png)


Patch values (**with** ntdll remapping):

```
NativeBypassCredGuard.exe patch true
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/Screenshot_2.png)

-------------------

## References

- [Revisiting a Credential Guard Bypass](https://itm4n.github.io/credential-guard-bypass/) by [itm4n](https://x.com/itm4n) - A great analysis from which I took the pattern for this tool

- [WDigest: Digging the dead from the grave](https://neuralhax.github.io/wdigest-digging-the-dead-from-the-grave) by [neuralhax](https://twitter.com/neuralhax) - An amazing blog that proves it is possible to use other values for *g_fParameter_UseLogonCredential*, I didn't test it for now but you can play with its value with the variable *useLogonCredential_Value* in Program.cs.


- [Exploring Mimikatz - Part 1 - WDigest](https://blog.xpnsec.com/exploring-mimikatz-part-1/) by [xpn](https://x.com/_xpn_)