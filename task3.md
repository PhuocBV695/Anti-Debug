# Tổng quan về Debugging  

# Debug Flags  
## Using Win32 API  
Các kỹ thuật antidebug trong mục này sẽ dùng winapi để nhận biết chương trình có bị debug hay không  
### IsDebuggerPresent()  
Api `IsDebuggerPresent()` được gọi từ kernel32/kernelbase, nếu bị debug, hàm sẽ trả về True (1), còn ngược lại sẽ trả về False (0), với asm thì sẽ trả về tại thanh ghi al  
Cơ chế của hàm này là kiểm tra trường `BeingDebugged` trong PEB:  
  
![image](https://github.com/user-attachments/assets/10e0cffd-2512-4265-bed7-b5b36d64d422)  
bypass trường `BeingDebugged` này khá đơn giản, ta có thể test bằng windbg  
tìm base address của PEB:  
![image](https://github.com/user-attachments/assets/f3c8edf6-6ad9-4f1a-b3c8-f8d112f73abb)  
cộng base address của PEB với offset:  
![image](https://github.com/user-attachments/assets/c41155fc-737f-4080-9415-57245d8bde5c)  
đổi giá trị tại `BeingDebugged` bằng lệnh `eb *address 00`:  
![image](https://github.com/user-attachments/assets/aba3a810-47f7-4b97-9572-9ad46e50d32c)  
Dễ dàng thấy `BeingDebugged` đã bị thay đổi -> trong suốt quá trình debug tại process này, `IsDebuggerPresent()` sẽ luôn trả về giá trị False (0)  
Tuy nhiên mình luôn thắc mắc là tuy trường `BeingDebugged` luôn cho ta biết chương trình luôn bị debug là thế nhưng làm sao chương trình nó biết nó đang bị debug để trả về (1) (ý là về mặt kỹ thuật)  
Và mình có tìm hiểu thì có tìm được 1 số thông tin như sau:  
Nếu ta chạy gdb, x64dbg, hoặc WinDbg để debug một tiến trình,  debugger sẽ làm như sau:  
Gọi API DebugActiveProcess(PID)  
  
![image](https://github.com/user-attachments/assets/9112efc8-eade-45d6-ab8a-9d9b1c3d07b1)  
khi đó Windows sẽ cho phép debugger attach vào process và debug  
và API này báo với Windows rằng tiến trình PID đang bị debug  
khi đó Windows Kernel cập nhật EPROCESS->DebugPort để trỏ đến debugger  
Hệ thống sẽ đặt PEB->BeingDebugged = 1   
ta có thể tìm hiểu thêm tại: http://www.shishirbhat.com/2013/09/windows-debugging-api-part-1.html  
code:  
```c
#include <stdio.h>
#include <windows.h>

int main() {
    if (IsDebuggerPresent()) {
        printf("Debugger detected!\n");
    } else {
        printf("No debugger detected.\n");
    }
    return 0;
}
```
ngoài ra, thông thường để bypass anti-debug khi reverse thì ta sẽ sửa giá trị thanh ghi eax hoặc cờ ZF:  
  
![image](https://github.com/user-attachments/assets/42599933-b529-40d4-b83a-e4afe8ddbb9c)  
hoặc:  

![image](https://github.com/user-attachments/assets/ff9b6449-adfb-4e57-9d02-b93e018cf3d8)   
về cơ bản cách bypass các anti-debug khác cũng tương tự vậy, nên mình về sau chỉ viết các cách bypass đặc thù cho mỗi loại và sẽ không nhắc lại cách này nữa  
### CheckRemoteDebuggerPresent()  
Hàm CheckRemoteDebuggerPresent() là một API thuộc kernel32/kernelbase được sử dụng để kiểm tra xem một tiến trình có đang bị debug từ xa hay không  
hàm này có khác với IsDebuggerPresent ở chỗ hàm này gọi NtQueryInformationProcess() ProcessDebugPort  

code:  
```c
#include <stdio.h>
#include <windows.h>

int main() {
    BOOL bDebuggerPresent;// thực ra đặt tên biến này là gì cũng được :P
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent)==1&&bDebuggerPresent==1)
        {printf("Debugger detected!");}
    else {printf("No debugger");}
    return 0;
}

```
### NtQueryInformationProcess()  
  
![image](https://github.com/user-attachments/assets/5b2b6ac0-ebc0-44f6-97e4-2c537d226f99)  
`PROCESSINFOCLASS` là một danh sách liệt kê chứa các giá trị xác định loại thông tin cần lấy từ một tiến trình  
một số giá trị cần chú ý:  
`ProcessDebugPort(0x7)`  
`ProcessDebugObjectHandle(0x1E)`  
`ProcessDebugFlags(0x1F)`  
#### ProcessDebugPort  
Cơ chế: kiểm tra DebugPort trong _EPROCESS  
```c
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG
);

int main() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    HANDLE DebugPort = NULL;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0x07, &DebugPort, sizeof(HANDLE), NULL);

    if (status == 0 && DebugPort) {
        printf("Process is being debugged!\n");
    } else {
        printf("Process is not being debugged.\n");
    }

    return 0;
}


```
về ProcessDebugObjectHandle và ProcessDebugFlags, cơ chế khác với ProcessDebugPort, tuy nhiên cách viết code anti-debug cũng tương tự, chỉ thay 0x07 thành 0x1e hoặc 0x1f  
# Object Handles  
phần này code không chạy được, bổ sung sau  
# Exceptions  
## UnhandledExceptionFilter()  
Trong Windows, nếu một chương trình gặp ngoại lệ (exception) nhưng không có handler nào để bắt lỗi đó, hệ thống sẽ gọi hàm UnhandledExceptionFilter() từ thư viện Kernel32.dll  
nếu dùng SetUnhandledExceptionFilter() thì khi có debugger, exception sẽ chuyển cho debugger  
code:  
```c
#include <stdio.h>
#include <Windows.h>

LONG nUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip \xCC\xEB\x??
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool Check()
{
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)nUnhandledExceptionFilter);
    __asm
    {
        int 3                      // CC
        jmp near being_debugged    // EB ??
    }
    bDebugged = false;

being_debugged:
    return bDebugged;
}

int main() {
    if (Check())
        printf("Debug!\n");
    else
        printf("NotDebug\n");
    return 0;
}
```
## RaiseException()  
Khi gọi hàm này, hệ điều hành sẽ tạo một ngoại lệ (exception) và kiểm tra xem có trình xử lý ngoại lệ nào có thể bắt được nó hay không  
nếu có debugger, chương trình sẽ chuyển sang cho debugger xử lý, còn không thì sẽ gọi UnhandledExceptionFilter()  
code:  
```c
bool Check()
{
    __try
    {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except(DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER 
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}
```
## Hiding Control Flow with Exception Handlers  
### SEH  
code:  
```c
#include<Windows.h>
#include<stdio.h>
int main(void)
{
    int a=0;
    __try
    {
        __asm int 3;
        a+=10;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    {
        printf("a = %d",a);
    }

    return 0;
}
```
nguyên lý là khi ta gọi ngoại lệ chỉ có debugger xử lý được (như là breakpoint int 3) thì khi không có debugger sẽ crash và nhảy qua except còn khi có debugger, bên trong __try vẫn được debugger xử lý và thực thi, làm cho kết quả giữa chương trình khi bị debug và không bị debug là khác nhau:  
Khi có debugger:  
  
![image](https://github.com/user-attachments/assets/82d78c2b-6721-49e5-8796-d1d4ff446e5c)  

khi không debug:  
  
![image](https://github.com/user-attachments/assets/7e946742-717d-40f4-a6ad-501e1ae53529)


