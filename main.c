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

    unsigned char magic[4];
    read(fd, magic, 4);

    if (magic[0] == 0x4D && magic[1] == 0x5A)
        printf("[+] PE format (Windows executable)\n");
    else if (magic[0] == 0x7F && magic[1] == 0x45 &&
             magic[2] == 0x4C && magic[3] == 0x46)
        printf("[+] ELF format (Linux/Unix executable)\n");
    else if (magic[0] == 0xCE || magic[0] == 0xCF)
        printf("[+] Mach-O format (macOS executable)\n");
    else if (magic[0] == 0xCA && magic[1] == 0xFE &&
             magic[2] == 0xBA && magic[3] == 0xBE)
        printf("[+] Java .class file\n");
    else
        printf("[?] Unknown format: %02x %02x %02x %02x\n",
               magic[0], magic[1], magic[2], magic[3]);

    lseek(fd, 0, SEEK_SET);

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

            if (next == 0x89 || next == 0x8B) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                if (next == 0x89)
                    printf("0x%04lx: mov %s, %s\n", offset-1, regs64[rm], regs64[reg]);
                else
                    printf("0x%04lx: mov %s, %s\n", offset-1, regs64[reg], regs64[rm]);
            }
            else if (next == 0x83) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int op = (modrm >> 3) & 0x7;
                int rm = modrm & 0x7;
                const char *ops[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
                signed char imm;
                read(fd, &imm, 1);
                offset++;
                printf("0x%04lx: %s %s, %d\n", offset-2, ops[op], regs64[rm], imm);
            }
            else if (next == 0x85) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                printf("0x%04lx: test %s, %s\n", offset-1, regs64[rm], regs64[reg]);
            }
            else if (next == 0x31) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                printf("0x%04lx: xor %s, %s\n", offset-1, regs64[rm], regs64[reg]);
            }
            else if (next == 0xFF) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int op = (modrm >> 3) & 0x7;
                int rm = modrm & 0x7;
                if (op == 0) printf("0x%04lx: inc %s\n", offset-1, regs64[rm]);
                else if (op == 1) printf("0x%04lx: dec %s\n", offset-1, regs64[rm]);
                else if (op == 2) printf("0x%04lx: call %s\n", offset-1, regs64[rm]);
                else if (op == 4) printf("0x%04lx: jmp %s\n", offset-1, regs64[rm]);
            }
            else if (next == 0xC7) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int rm = modrm & 0x7;
                int imm;
                read(fd, &imm, 4);
                offset += 4;
                printf("0x%04lx: mov %s, %d\n", offset-4, regs64[rm], imm);
            }
            else if (next == 0x01) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                printf("0x%04lx: add %s, %s\n", offset-1, regs64[rm], regs64[reg]);
            }
            else if (next == 0x29) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                printf("0x%04lx: sub %s, %s\n", offset-1, regs64[rm], regs64[reg]);
            }
            else if (next == 0x3B) {
                unsigned char modrm;
                read(fd, &modrm, 1);
                offset++;
                int reg = (modrm >> 3) & 0x7;
                int rm  = modrm & 0x7;
                printf("0x%04lx: cmp %s, %s\n", offset-1, regs64[reg], regs64[rm]);
            }
            else printf("0x%04lx: rex.w + 0x%02x\n", offset, next);
            }
        // mov r32, r/m32
        else if (byte == 0x89) {
            unsigned char modrm;
            read(fd, &modrm, 1);
            offset++;
            int reg = (modrm >> 3) & 0x7;
            int rm  = modrm & 0x7;
            printf("0x%04lx: mov %s, %s\n", offset-1, regs32[rm], regs32[reg]);
        }
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