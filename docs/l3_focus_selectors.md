# `l3_focus` selectors — vocabulary

Each entry in a scope profile's `l3_focus` list tells the L3 function gate which handlers to promote for full pseudo-C decompilation. Entries are either **generic selectors** (interpreted by the pipeline core as reusable patterns) or **profile-specific heuristics** (semantic hints that require dedicated L3 code).

## Generic selectors (implemented by the pipeline core)

Every profile may use these; the pipeline interprets them without additional per-profile code.

### `handlers_dispatched_from_matching_ioctl`

Promote every dispatch handler whose IOCTL code matches any pattern in the profile's `ioctl_patterns`.

### `functions_calling_any_of_must_have_one`

Promote every function (handler or helper) that calls any import listed in `imports_of_interest.must_have_one`.

### `functions_reaching_sink: <list_name>`

Parameterized form. Promote every function that reaches, through static call-graph traversal, any symbol in the profile list referenced by `<list_name>`. The parameter must be the name of another top-level field on the same profile — typically `taint_sinks`.

Example:

```yaml
l3_focus:
  - functions_reaching_sink: taint_sinks
```

## Profile-specific heuristics (require dedicated L3 code)

These are allowed, but each one needs its own implementation in the L3 stage. The pipeline logs a warning and falls back to only the generic selectors if a profile references a heuristic the current L3 build does not implement. This degradation is intentional: scope profiles can describe the *ideal* L3 scope ahead of implementation without blocking the rest of the pipeline.

Observed in the shipped profiles:

| Selector | Profile | Intent |
|---|---|---|
| `handlers_on_input_class_devices_with_METHOD_NEITHER` | `hid-input-control` | Promote handlers that live on devices classified as `hid` or `input` **and** whose dispatch method is `METHOD_NEITHER`. |
| `functions_that_write_to_EPROCESS_token_offset` | `process-token-manipulation` | Promote functions that write to the token offset of an `EPROCESS` structure (requires offset-aware pattern recognition). |
| `functions_writing_port_B2_or_user_controlled_port` | `smm-smi` | Promote functions that call `WRITE_PORT_UCHAR` with a port argument that is either the APMC constant (0xB2) or traceable to user input. |
| `functions_building_smm_communication_buffer` | `smm-smi` | Promote functions that stage a communication buffer in UC-mapped memory before an SMI trigger. |
| `functions_opening_user_named_physical_drive` | `disk-raw-io` | Promote functions that call `ZwCreateFile` / `IoGetDeviceObjectPointer` with a device name derived from user input and matching `\Device\PhysicalDrive*`, `\Device\Harddisk*`, etc. |

## Adding a new selector

- **Generic selector** — add it to this document, add the interpretation code to the pipeline's L3 gate, no schema change required (`l3_focus` items are free-form strings or single-key objects).
- **Profile-specific heuristic** — add it here under the profile that needs it, implement the dedicated detector in L3, and document how the pipeline behaves when the heuristic is referenced but not yet implemented (warning + fallback to generic selectors).

## Hard rule

A profile may reference heuristics that the current L3 build does not implement. The pipeline degrades gracefully: the generic selectors still run, and the gap is reported in the bundle's `summary.md` with the exact selector name and the profile that referenced it. Operators triaging an incomplete bundle can then prioritize which heuristic to implement next.
