# differ

A CLI tool for comparing two binary files with visual highlighting of differences

## Features

- Hex and ASCII diff with colored highlighting
- Disassembles and compares differing code sections
- Skips PE signature section by default (can be diffed with option)
- Compares some PE/ELF header fields (only if they differ)
- Supports PE and ELF formats

## Install & Usage

```
$ pip install .
```

The `differ` command is now available:

```
$ differ --help
usage: differ [-h] [--diff-signature] file1 file2

positional arguments:
  file1             The first file to compare
  file2             The second file to compare

options:
  -h, --help        show this help message and exit
  --diff-signature  Diff the signature section of the PE file
```

Examples:

```
$ differ ButtonsDxe.efi ButtonsDxe.patched.efi
Comparing ButtonsDxe.efi and ButtonsDxe.patched.efi...
Hex diff:
<000036d0       05 00 00 14 10 1c 00 12  30 03 00 34 51 20 80 52        |........0..4Q .R|
---
<000036d0       05 00 00 14 10 1c 00 12  30 03 00 34 b1 01 80 52        |........0..4...R|
<000036e0       f1 33 00 79 88 02 40 39  e1 63 00 91 e2 03 1e 32        |.3.y..@9.c.....2|
---
<000036e0       f1 37 00 79 88 02 40 39  e1 63 00 91 e2 03 1e 32        |.7.y..@9.c.....2|
Disassembly diff:
<000036dc       mov     w17, #0x102
---
>000036dc       mov     w17, #0xd
<000036e0       strh    w17, [sp, #0x18]
---
>000036e0       strh    w17, [sp, #0x1a]
```