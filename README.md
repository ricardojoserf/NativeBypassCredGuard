# NativeBypassCredGuard

NativeBypassCredGuard is a tool designed to bypass Credential Guard by patching wdigest.dll using only NTAPI functions (functions exported by ntdll.dll).

It locates the pattern "39 ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00" in the wdigest.dll file on disk (as described in the blog post in the References section; this pattern is present in this file in all Windows versions), calculates the memory addresses, and patches the value of two variables within wdigest.dll: *g_fParameter_UseLogonCredential* (to 1) and *g_IsCredGuardEnabled* (to 0).

Using only NTAPI functions, it is possible to remap the ntdll.dll library to bypass user-mode hooks and security mechanisms, which is an optional feature of the tool. If used, a clean ntdll.dll is obtained from a process created in debug mode.


The NTAPI functions needed are:

![poc](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/esquema.png)

- NtOpenProcessToken and NtAdjustPrivilegesToken to enable the SeDebugPrivilege privilege
- NtCreateFile and NtReadFile to open a handle to the DLL file on disk and read its bytes
- NtGetNextProcess and NtQueryInformationProcess to get a handle to the lsass process
- NtReadVirtualMemory and NtQueryInformationProcess to get the wdigest.dll base address
- NtReadVirtualMemory to read the values of the variables
- NtWriteProcessMemory to write new values to the variables

-------------------

## Usage

```
NativeBypassCredGuard <OPTION> <REMAP-NTDLL>
```

**Option** (required):
- **check**: Read current values.
- **patch**: Write new values.

**Remap ntdll** (optional):
- **true**: Remap the ntdll library.
- **false** (or omitted): Do not remap the ntdll library.


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

- [Revisiting a Credential Guard Bypass](https://itm4n.github.io/credential-guard-bypass/) by [itm4n](https://x.com/itm4n)
