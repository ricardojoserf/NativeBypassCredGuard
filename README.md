# NativeBypassCredGuard

Bypass Credential Guard using only NTAPIs by patching the *g_IsCredGuardEnabled* and *g_fParameter_UseLogonCredential* values in wdigest.dll.

It searches the pattern "39 ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00" in the wdigest.dll library (as explained in [itm4n's blog post from 2022](https://itm4n.github.io/credential-guard-bypass/), this works for all recent Windows versions), calculates the address in memory and patches the variables (*g_IsCredGuardEnabled* is set to 0 and *g_fParameter_UseLogonCredential* is set to 1)

The NTAPIs needed for this are:

![poc](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/esquema.png)

- NtOpenProcessToken and NtAdjustPrivilegesToken to enable SeDebugPrivilege privilege
- NtCreateFile and NtReadFile to open a handle to the DLL file in disk and read its bytes
- NtGetNextProcess and NtQueryInformationProcess to get a handle to the lsass process
- NtReadVirtualMemory to read the value of the variables 
- NtWriteProcessMemory to write new values to the variables


-------------------

## Usage

```
NativeBypassCredGuard <OPTION> <REMAP-NTDLL>
```

Option (first argument):
- 'check': Read current values.
- 'patch': Write new values.

Remap ntdll (second argument):
- true: Remap the ntdll library.
- false (or omitted): Do not remap the ntdll library.


-------------------

## Examples

Read current values without remapping the ntdll library:

```
NativeBypassCredGuard.exe check
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/Screenshot_1.png)


Write new values and remap the ntdll library:

```
NativeBypassCredGuard.exe patch true
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/nativebypasscredguard/Screenshot_2.png)


-------------------

## References

- [Revisiting a Credential Guard Bypass
](https://itm4n.github.io/credential-guard-bypass/)
