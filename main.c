#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

// ModRM
// [ mod(2) | reg(3) | r/m(3) ]
//   bit7-6    bit5-3   bit2-0

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Cannot open file: %s\n", argv[1]);
        return 1;
    }

    unsigned char byte;
    long offset = 0;
    const char *regs32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
    const char *regs64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};

    while (read(fd, &byte, 1) == 1) {

        // single byte
        if (byte == 0xC3) printf("0x%04lx: ret\n", offset);
        else if (byte == 0x55) printf("0x%04lx: push rbp\n", offset);
        else if (byte == 0x5D) printf("0x%04lx: pop rbp\n", offset);
        else if (byte == 0x53) printf("0x%04lx: push rbx\n", offset);
        else if (byte == 0x56) printf("0x%04lx: push rsi\n", offset);
        else if (byte == 0x57) printf("0x%04lx: push rdi\n", offset);
        else if (byte == 0x5B) printf("0x%04lx: pop rbx\n", offset);
        else if (byte == 0x5E) printf("0x%04lx: pop rsi\n", offset);
        else if (byte == 0x5F) printf("0x%04lx: pop rdi\n", offset);
        else if (byte == 0x90) printf("0x%04lx: nop\n", offset);
        else if (byte == 0xCC) printf("0x%04lx: int3\n", offset);

        // je - short jump, 1 byte operand
        else if (byte == 0x74) {
            signed char rel;
            read(fd, &rel, 1);
            offset++;
            printf("0x%04lx: je -> 0x%04lx\n", offset-1, offset + rel);
        }

        // jne - short jump, 1 byte operand
        else if (byte == 0x75) {
            signed char rel;
            read(fd, &rel, 1);
            offset++;
            printf("0x%04lx: jne -> 0x%04lx\n", offset-1, offset + rel);
        }

        // call - 4 byte operand
        else if (byte == 0xE8) {
            int rel;
            read(fd, &rel, 4);
            offset += 4;
            printf("0x%04lx: call -> 0x%04lx\n", offset-4, offset + rel);
        }

        // jmp - 4 byte operand
        else if (byte == 0xE9) {
            int rel;
            read(fd, &rel, 4);
            offset += 4;
            printf("0x%04lx: jmp -> 0x%04lx\n", offset-4, offset + rel);
        }

        // REX.W prefix - 64-bit
        else if (byte == 0x48) {
            unsigned char next;
            read(fd, &next, 1);
            offset++;
            if (next == 0x89) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                printf("0x%04lx: mov %s, %s\n", offset-1, regs64[rm], regs64[reg]);
            }
            else if (next == 0x8B) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                printf("0x%04lx: mov %s, %s\n", offset-1, regs64[reg], regs64[rm]);
            }
            else printf("0x%04lx: rex.w + 0x%02x\n", offset, next);
        }

        // mov r/m32, r32
        else if (byte == 0x89) {
            unsigned char modrm;
            read(fd, &modrm, 1);
            offset++;
            int reg = (modrm >> 3) & 0x7;
            int rm  = modrm & 0x7;
            printf("0x%04lx: mov %s, %s\n", offset-1, regs32[rm], regs32[reg]);
        }

        // mov r32, r/m32
        else if (byte == 0x8B) {
            unsigned char modrm;
            read(fd, &modrm, 1);
            offset++;
            int reg = (modrm >> 3) & 0x7;
            int rm  = modrm & 0x7;
            printf("0x%04lx: mov %s, %s\n", offset-1, regs32[reg], regs32[rm]);
        }

        offset++;
    }

    close(fd);
    return 0;
}