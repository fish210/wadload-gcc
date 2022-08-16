/*
printf("交流群：905600556");
这个半成品 还有一半自己去领悟，只提供一些研究思路
使用 GCC12编译器，我的群提供下载，winlibs-i686-posix-dwarf-gcc-12.1.0-mingw-w64ucrt-10.0.0-r2
命令行：gcc -shared -o wadpatch.dll
DLL文件使用驱动注入器或输入法输入
*/

#include <windows.h>

extern "C" __declspec(dllexport) void WINAPI Easy_hook();

DWORD hook_address = 0x006EA8D5;              // hook地址
DWORD CallAddress = 0x006E4750;               // call地址
DWORD hook_return_address = hook_address + 5; // hook跳回地址
static BYTE *empty_memory;                    // 空白内存

void WINAPI WadLoadCall(const char *WadPath, DWORD Esi_) // 加载call
{
    DWORD address = CallAddress;
    char *buffer = new char[MAX_PATH]{}; // 申请内存
    strcpy_s(buffer, MAX_PATH, WadPath);
    DWORD wadpath = (DWORD)buffer;
    DWORD output_temp;
    asm volatile("push %1\n"
                 "push %2\n"
                 "call *%3\n"
                 : "=r"(output_temp)
                 : "r"(wadpath), "r"(Esi_), "r"(address)
                 : "%esi");
    delete[] buffer; // 释放内存
}
void Hook_function(DWORD esi) // 挂接函数，我们自己的call
{
    WadLoadCall("skn/1.wad", esi);
}
void WINAPI Easy_hook() // 功能函数
{
    //保存 "push地址" 5个字节
    BYTE old_PushCore[5] = {0};
    ReadProcessMemory(INVALID_HANDLE_VALUE, (LPVOID)hook_address, old_PushCore, 5, 0);
    //申请一块空白内存 改为可读可写权限
    empty_memory = new BYTE[100]{};                               //申请内存100个字节
    DWORD old_Protect = 0;                                        //旧保护属性
    DWORD new_Protect = PAGE_EXECUTE_READWRITE;                   //新保护属性
    VirtualProtect(empty_memory, 100, new_Protect, &old_Protect); //修改内存属性

    //前半段 core
    BYTE CallBackCore[11] = {0x60, 0x56, 0XE8, 0, 0, 0, 0, 0x83, 0xC4, 0x04, 0x61};
    WriteProcessMemory(INVALID_HANDLE_VALUE, (LPVOID)empty_memory, CallBackCore, 11, 0);
    DWORD callback_address = (DWORD)Hook_function - (DWORD)(empty_memory + 2) - 5;
    *(DWORD *)(&empty_memory[0] + 3) = callback_address; //挂接函数机器码 4字节
    DWORD old_data_index = 11;                           //还原数据 起始位置

    //后半段 core
    //"push地址" 5个字节 写到空白内存
    WriteProcessMemory(INVALID_HANDLE_VALUE, empty_memory + old_data_index, old_PushCore, 5, 0);
    //"jmp x" 5个字节 写到空白内存
    empty_memory[old_data_index + 5] = 0xE9;                                                        // jmp + 4字节
    DWORD empty_jmp_address = hook_return_address - (DWORD)(empty_memory + old_data_index + 5) - 5; //公式：目标地址 - 当前地址 - 5
    *(DWORD *)(&empty_memory[0] + (old_data_index + 5 + 1)) = empty_jmp_address;

    //机器码 写到HOOK地址
    BYTE jmp_code[5] = {0xE9, 0, 0, 0, 0};
    DWORD hook_jmp_addr = (DWORD)empty_memory - hook_address - 5;
    *(DWORD *)(&jmp_code[0] + 1) = hook_jmp_addr;
    WriteProcessMemory(INVALID_HANDLE_VALUE, (LPVOID)hook_address, jmp_code, 5, 0);
    return;
    // delete[] empty_memory;//释放内存
}