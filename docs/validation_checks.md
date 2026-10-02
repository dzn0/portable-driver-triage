# `validation_expected` vocabulary

Each entry in a scope profile's `validation_expected` list names a check that the handler **ought to perform** on user input or operation parameters. The L3 validation-gap detector scans each promoted handler and reports entries from this list that are missing.

Vocabulary is intentionally stable: adding a new value requires implementing a corresponding detector in L3. An entry whose detector is not implemented is silently ignored by the gap pass and reported as "detector not implemented" in the bundle's `summary.md`.

## Generic checks (apply to any kernel driver)

These are the standard IRP-handling disciplines; most drivers that pass user input to privileged primitives should perform them.

| Name | What it means |
|---|---|
| `ProbeForRead` | A call to `ProbeForRead` on the user buffer before dereferencing it, in `METHOD_NEITHER` paths. |
| `ProbeForWrite` | Equivalent for writes. |
| `input_length_check` | The handler verifies `Parameters.DeviceIoControl.InputBufferLength` meets its minimum before touching the buffer. |
| `output_length_check` | Equivalent for `OutputBufferLength`. |
| `caller_privilege_check` | The handler checks that the caller holds at least Administrator / `SeDebugPrivilege` / integrity level High before granting the capability. **Broadest form.** |
| `caller_integrity_check` | Narrower form: integrity level check only (not full privilege). **Satisfies `caller_privilege_check`.** |
| `caller_sid_check` | Narrower form: SID allowlist / denylist check. **Satisfies `caller_privilege_check`.** |
| `caller_session_check` | The handler checks the caller is in session 0 or in an interactive session, as appropriate. Orthogonal to the privilege hierarchy. |

## Scope-specific checks

These are only meaningful inside a specific vulnerability class. The L3 detector must know the context (which primitive is being guarded) to recognize them.

| Name | Profile | What it means |
|---|---|---|
| `target_pid_allowlist_check` | `process-token-manipulation` | PID the handler operates on is restricted to a known-safe list (or at least excludes PIDs ≤ 4). |
| `no_system_pid_target_check` | `process-token-manipulation` | Explicit refusal to operate on PID 4 (System) or on protected processes. |
| `target_device_allowlist_check` | `disk-raw-io` | Device name opened by the handler is restricted to a known-safe list (not any user-named `\Device\Harddisk*`). |
| `no_system_volume_target_check` | `disk-raw-io` | Explicit refusal to operate on `C:\` / the system volume. |
| `offset_and_length_sanity_check` | `disk-raw-io` | Offset + length arithmetic is bounded; no integer overflow. |
| `msr_number_allowlist_check` | `msr-access` | MSR index passed to `__writemsr` is restricted to a known-safe list. |
| `cr_value_sanity_check` | `msr-access` | Value written to CR0 / CR3 / CR4 preserves required protection bits (e.g., SMEP, SMAP). |
| `port_number_pinned_check` | `smm-smi` | Port written by `WRITE_PORT_UCHAR` is pinned to a constant (not derived from user input). |
| `smi_number_allowlist_check` | `smm-smi` | SMI number written to APMC is restricted to a known-safe list. |
| `comm_buffer_integrity_check` | `smm-smi` | The SMM communication buffer passes an integrity / signature check before use. |

## Naming conventions

- All lowercase, snake_case.
- Generic checks are named after the Windows API or discipline (`ProbeForRead`), preserving the API casing.
- Scope-specific checks follow `<subject>_<policy>_check`: `target_pid_allowlist_check`, `smi_number_allowlist_check`.

## Caller-check hierarchy — formal rule

Three names refer to overlapping concerns around who is allowed to invoke the handler:

```
caller_privilege_check  (broadest — any Administrator / SeDebugPrivilege / High-integrity check)
    ├── caller_integrity_check   (narrower: integrity level only)
    └── caller_sid_check         (narrower: SID allowlist/denylist only)
```

**Implication rule enforced by the L3 detector:** if a handler satisfies either `caller_integrity_check` or `caller_sid_check`, it also satisfies `caller_privilege_check`. The reverse is not true — a generic privilege check does not imply either narrower variant.

A profile may list the broader form, the narrower form, or both. Listing only the narrower form means "I specifically want to know if THIS variant is present"; listing both means "either satisfies me." `caller_session_check` is orthogonal to this hierarchy and is not implied by any of the three.

## Resolved consolidations

- **`input_buffer_length_check` → `input_length_check`.** The two were duplicates; `input_length_check` is canonical and `input_buffer_length_check` was removed from `scope_profiles/hid-input-control.yaml`.
