# NativeBypassCredGuard

NativeBypassCredGuard is a tool designed to bypass Credential Guard by patching WDigest.dll using only NTAPI functions (exported by ntdll.dll). It is available in two flavours: C# and C++.

The tool locates the pattern "39 ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00" in the WDigest.dll file on disk (as explained in the first post in the Refences section, the pattern is present in this file in all Windows versions), then calculates the necessary memory addresses, and finally patches the value of two variables within WDigest.dll: *g_fParameter_UseLogonCredential* (to 1) and *g_IsCredGuardEnabled* (to 0).

This forces plaintext credential storage in memory, ensuring that from that point forward credentials are stored in cleartext whenever users log in. As a result, next time the LSASS process is dumped it may contain passwords in plaintext.


The NTAPI functions used are:

![poc](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/esquema.png)

- NtOpenProcessToken and NtAdjustPrivilegesToken to enable the SeDebugPrivilege privilege
- NtCreateFile and NtReadFile to open a handle to the DLL file on disk and read its bytes
- NtGetNextProcess and NtQueryInformationProcess to get a handle to the lsass process
- NtReadVirtualMemory and NtQueryInformationProcess to get the WDigest.dll base address
- NtReadVirtualMemory to read the values of the variables
- NtWriteProcessMemory to write new values to the variables

Using only NTAPI functions, it is possible to remap the ntdll.dll library to bypass user-mode hooks and security mechanisms, which is an optional feature of the tool. If used, a clean version of ntdll.dll is obtained from a process created in debugged mode.


-------------------

## Usage

```
NativeBypassCredGuard <OPTION> <REMAP-NTDLL>
```

**Option** (required):
- **check**: Read current values
- **patch**: Write new values

**Remap ntdll** (optional):
- **true**: Remap the ntdll library
- **false** (or omitted): Do not remap the ntdll library


-------------------

## Examples

**Read values** (**without** ntdll remapping):

```
NativeBypassCredGuard.exe check
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/Screenshot_1.png)


**Patch values** (**with** ntdll remapping):

```
NativeBypassCredGuard.exe patch true
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/Screenshot_2.png)



-------------------

## References

- [Revisiting a Credential Guard Bypass](https://itm4n.github.io/credential-guard-bypass/) by [itm4n](https://x.com/itm4n) - A great analysis from which I took the pattern to search the .text section of the DLL

- [WDigest: Digging the dead from the grave](https://neuralhax.github.io/wdigest-digging-the-dead-from-the-grave) by [neuralhax](https://twitter.com/neuralhax) - An amazing blog that proves it is possible to use other values for *g_fParameter_UseLogonCredential*, I didn't test it yet but you can play with the variable *useLogonCredential_Value*

- [Exploring Mimikatz - Part 1 - WDigest](https://blog.xpnsec.com/exploring-mimikatz-part-1/) by [xpn](https://x.com/_xpn_) - Fantastic blog post reverse-engineering and explaining WDigest credential caching
