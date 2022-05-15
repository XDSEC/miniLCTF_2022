#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define OPCODE_N 5
#define FLAG_LEN 16
#define ROL(value, bits) ((value << bits) | (value >> (sizeof(value) * 8 - bits)))
#define ROR(value, bits) ((value >> bits) | (value << (sizeof(value) * 8 - bits)))
unsigned long int k[2] = {0x64627421, 0x79796473};
// flag == I_hate_U_r1sc-V!
unsigned char vm_code[] = {
    0xf3, 0, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 4, 11, 0xf5,
    0xf3, 2, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 4, 11, 0xf5,
    0xf1, 0xff};
unsigned long int cipher[4] = {0x4bc21dbb95ef82ca, 0xf57becae71b547be, 0x80a1bdab15e7f6cd, 0xa3c793d7e1776385};
unsigned long int final[4] = {};
unsigned long int ipt[4] = {};
typedef struct vm_signal
{
    unsigned char opcode;
    void (*handler)(void *);
} vm_signal;
typedef struct vm_cpu
{
    int eip;
    unsigned long int X;
    unsigned long int Y;
    vm_signal op_list[OPCODE_N];
} vm_cpu;
int loop_cnt = 0;
int final_cnt = 0;
void my_check(vm_cpu *cpu);
void my_loop(vm_cpu *cpu);
void my_rol(vm_cpu *cpu);
void my_add(vm_cpu *cpu);
void my_push(vm_cpu *cpu);
void vm_init(vm_cpu *cpu)
{
    cpu->eip = 0;

    cpu->op_list[0].opcode = 0xf1;
    cpu->op_list[0].handler = my_check;

    cpu->op_list[1].opcode = 0xf2;
    cpu->op_list[1].handler = my_loop;

    cpu->op_list[2].opcode = 0xf3;
    cpu->op_list[2].handler = my_add;

    cpu->op_list[3].opcode = 0xf4;
    cpu->op_list[3].handler = my_rol;

    cpu->op_list[4].opcode = 0xf5;
    cpu->op_list[4].handler = my_push;
}
void vm_dispatcher(vm_cpu *cpu)
{
    for (int i = 0; i < OPCODE_N; i++)
    {
        if (vm_code[(cpu->eip)] == cpu->op_list[i].opcode)
        {
            (cpu->op_list[i]).handler(cpu);
            break;
        }
    }
}
void vm_start(vm_cpu *cpu)
{
    while (vm_code[(cpu->eip)] != 0xff)
    {
        vm_dispatcher(cpu);
    }
}
void my_add(vm_cpu *cpu)
{

    cpu->X = ipt[vm_code[(cpu->eip) + 1]] + k[0];
    cpu->Y = ipt[vm_code[(cpu->eip) + 1] + 1] + k[1];
    cpu->eip += 2;
}
void my_rol(vm_cpu *cpu)
{
    if (vm_code[(cpu->eip) + 1] == 0xe1)
    {
        cpu->X = ROL((cpu->X ^ cpu->Y), cpu->Y) + k[0];
    }
    if (vm_code[(cpu->eip) + 1] == 0xe2)
    {
        cpu->Y = ROL((cpu->X ^ cpu->Y), cpu->X) + k[1];
    }
    cpu->eip += 2;
}
void my_push(vm_cpu *cpu)
{
    final[final_cnt] = cpu->X;
    final[final_cnt + 1] = cpu->Y;
    cpu->X = 0;
    cpu->Y = 0;
    final_cnt += 2;
    cpu->eip += 1;
}
void my_check(vm_cpu *cpu)
{
    for (int i = 0; i < 4; i++)
    {
        if (final[i] != cipher[i])
        {
            printf("Wrong!");
            exit(0);
        }
    }
    cpu->eip += 1;
}
void my_loop(vm_cpu *cpu)
{
    // printf("%x %x %x",vm_code[cpu->eip],vm_code[(cpu->eip)+1],vm_code[(cpu->eip)+2]);

    if (loop_cnt < vm_code[(cpu->eip) + 2])
    {
        cpu->eip -= vm_code[(cpu->eip) + 1];
        // printf("%x",vm_code[cpu->eip]);
        loop_cnt++;
        // printf("Loop %d\t",loop_cnt);
    }
    else
    {
        loop_cnt = 0;
        cpu->eip += 3;
    }
}
int main()
{
    vm_cpu cpu = {0};
    puts("Input your flag");
    scanf("%16s", ipt);
    vm_init(&cpu);
    vm_start(&cpu);
    printf("Right!");
    return 0;
}
