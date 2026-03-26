# x86 Disassembler

A simple x86-64 disassembler written in C using POSIX file descriptors.
Reads raw PE binaries and decodes common x86-64 instructions with operands.

## Usage
```bash
./disassembler <binary>
```

## Example
```bash
./disassembler notepad.exe

0x1094: push rbp
0x10ac: mov rax, rbx
0x10f7: je -> 0x1112
0x1199: call -> 0x2340
0x11b1: pop rbp
0x11b2: ret
```

## Supported Instructions
- `ret`, `nop`, `int3`
- `push`/`pop` — rbp, rbx, rsi, rdi
- `je`, `jne` — short jumps with destination address
- `jmp`, `call` — near jumps with destination address
- `mov` — 32-bit and 64-bit (REX.W prefix), with register operands decoded

## Tested on
- Windows PE binaries (notepad.exe, calc.exe)

## Built with
- C
- POSIX file descriptors (open/read/close)