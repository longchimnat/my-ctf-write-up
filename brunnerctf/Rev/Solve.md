
# KPWhy

## Summary

`kpiman` is an unstripped ELF binary that reads a 44-byte "employee ID" and
runs it through three validation functions; the flag is the input itself,
echoed back once all three checks pass. Each function checks a different
15/15/14-byte slice of the input using a distinct reversible transform
(XOR, chained addition, S-box lookup), so each slice can be recovered
independently and then joined into the full flag.

## Solution

### Step 1: Read `main` and the three check functions

The binary is not stripped, so symbol names are intact: `calculateSynergy`,
`measureVelocity`, `assessAlignment`, plus four `.rodata` tables (`kpi_alpha`,
`kpi_beta`, `kpi_gamma`, `synergy_table`). `main` enforces `strlen(input) == 44`,
calls all three functions, and only prints the "Promotion code" (the flag)
if all three return true — so the flag is simply the correct 44-byte input.

Decompiling each function shows:

- **`calculateSynergy`** (bytes 0–14): `input[i] XOR ((i*7+42) & 0xFF) == kpi_alpha[i]`
- **`measureVelocity`** (bytes 15–29): `input[i] + input[i-1] == kpi_beta[i-15]` (32-bit ints)
- **`assessAlignment`** (bytes 30–43): `synergy_table[input[i]] == kpi_gamma[i-30]`

All four tables were dumped with `objdump -s -j .rodata kpiman` and hardcoded
into the solve script below.

```python
import struct

# Bytes pulled directly from the .rodata section (objdump -s -j .rodata kpiman)
kpi_alpha = bytes.fromhex("48434d51282826201b590505" + "21eefc00")
kpi_beta = struct.unpack("<15i", bytes.fromhex(
    "a1000000a4000000d2000000c0000000d3000000a5000000"
    "92000000cd0000009e000000a4000000d3000000cb000000"
    "9c00000060000000" + "9b000000"
))
kpi_gamma = bytes.fromhex("d3c06beeb6ea6dee5d08dcdc" + "8390")
synergy_table = bytes.fromhex(
    "665e9e1022f67d0dd5aace920c51152c"
    "12b105becda01fad63c20325488543e0"
    "b78b540e89c6ff32f0bd423bf139741b"
    "4c942034dfafba6a6d5752e246e5fda4"
    "bcf9cfc4fa60b081f85a07fc296168b8"
    "2d3f76d64fd2ddb95853eb7262a728ee"
    "7abf5d4ddc65b36bf5d306786f2ac0ca"
    "243eeac9b208ae70d88331971e908400"
    "14de1c967f8dfb798f18a34b41feda16"
    "1137c39f02a1697b7ed0a5e3e4303599"
    "9d5cec4a2b5650c1ed80e75b49d1a90b"
    "1d591738c59a86c7db6e4ee955d713c8"
    "8e198ae1f4820a36ef40d9272144751a"
    "26d4870195719823453a2eab7733a27c"
    "6c3d09f747cbb4bbf3a664f2733ccc93"
    "04b667e82f0f88b5e69c8cac5fa8919b"
)

flag = [None] * 44

# calculateSynergy: bytes 0-14, XOR with an index-dependent key
for i in range(15):
    key = (i * 7 + 42) & 0xFF
    flag[i] = chr(kpi_alpha[i] ^ key)

# measureVelocity: bytes 15-29, chained addition seeded by flag[14]
for i in range(15, 30):
    target = kpi_beta[i - 15]
    flag[i] = chr(target - ord(flag[i - 1]))

# assessAlignment: bytes 30-43, reverse S-box lookup (brute force 256 candidates)
for i in range(30, 44):
    target = kpi_gamma[i - 30]
    flag[i] = chr(next(b for b in range(256) if synergy_table[b] == target))

print("".join(flag))
```

Output:

```
brunner{y0ur_kp1s_ar3_n0t_l00king_gr8_buddy}
```

### Step 2: Verify against the binary

```
$ echo "brunner{y0ur_kp1s_ar3_n0t_l00king_gr8_buddy}" | ./kpiman
BrunnerCorp KPIman v3.1
Enter employee ID: Analyzing synergy...
Productivity: 100%. Finally, someone who gets it.
Promotion code: brunner{y0ur_kp1s_ar3_n0t_l00king_gr8_buddy}
```

## Flag

```
brunner{y0ur_kp1s_ar3_n0t_l00king_gr8_buddy}
```