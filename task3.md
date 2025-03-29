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
hàm này có khác với IsDebuggerPresent ở chỗ hàm này gọi NtQueryInformationProcess() ProcessDebugPort thay vì lấy giá trị ở `BeingDebugged`  

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
Các kỹ thuật anti-debug mục này khá hay và khá khó khăn cho việc xác định luồng và bypass anti-debug, không đơn thuần chỉ là kiểm tra if-else như mục DebugFLags  
## UnhandledExceptionFilter()  
code:  
```c
#include <stdio.h>
#include <Windows.h>

LONG nUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
    printf("hoho\n");
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip \xCC\xEB\x??
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool Check()
{
    printf("hehe\n");
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)nUnhandledExceptionFilter);
    printf("lala\n");
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
nguyên lý là: khi ta đăng ký hàm nUnhandledExceptionFilter() (hàm bất kỳ, bất cứ tên nào) với SetUnhandledExceptionFilter(), khi có debugger, chương trình sẽ chạy qua mà không thực thi hàm nUnhandledExceptionFilter() mà ta đã đăng ký.  
còn khi không debug, chương trình sẽ chạy bình thường cho đến khi gặp ngoại lệ, sẽ thực thi hàm nUnhandledExceptionFilter() mà ta đã đăng ký, sau đó vẫn tiếp tục chương trình ngay tại địa chỉ được push vào đỉnh stack.  
Khi debug:  

![image](https://github.com/user-attachments/assets/bf7313a1-7edf-46ac-9688-b9fc604a9fda)  
Khi không debug (hãy chú ý thứ tự thực thi):  

![image](https://github.com/user-attachments/assets/ee082fc7-94cb-44e7-adbc-b0f3771fca22)  
  
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

### VEH  
code:  
```c
#include<Windows.h>
#include<stdio.h>

PVOID g_pLastVeh = nullptr;
int a = 0;

LONG WINAPI ExeptionHandler1(PEXCEPTION_POINTERS pExceptionInfo)
{
    a+=5;
    printf("a = %d", a);
    ExitProcess(0);
}

int main(void)
{
    g_pLastVeh = AddVectoredExceptionHandler(TRUE, ExeptionHandler1);
    printf("hehe\n");
    if (g_pLastVeh) {
        __asm int 3;
        a += 10;
    }
    printf("a = %d", a);
    return 0;
}
```
nguyên lý là: đăng ký ExeptionHandler1 với AddVectoredExceptionHandler để khi gặp ngoại lệ mà không xử lý được, chương trình sẽ nhảy vào hàm ExeptionHandler1()  
Tức là chương trình khi không có debugger sẽ chạy hết cho đến khi gặp ngoại lệ, sẽ nhảy vào hàm ExeptionHandler1() còn nếu ngoại lệ có thể xử lý được, sẽ chạy tiếp mà không nhảy vào hàm ExeptionHandler1()  
khi không debug:  
  
![image](https://github.com/user-attachments/assets/77b79592-44cb-4e24-88ea-687c17ef43ab)  
ta thấy chương trình đã thực hiện in "hehe" và khi gặp ngoại lệ, đã thực thi hàm ExeptionHandler1() thay vì tiếp tục hàm main()  
khi debug:  

![image](https://github.com/user-attachments/assets/1ec8ec8b-a1fc-4028-9a9e-cd02381a21a8)  
ta thấy chương trình không nhảy vào ExeptionHandler1() mà vẫn tiếp tục cho đến hết chương trình.  
Tuy có vẻ giống nhau nhưng ta có thể dễ dàng nhận thấy điểm khác nhau giữa AddVectoredExceptionHandler và SetUnhandledExceptionFilter():  
sau khi thực thi hàm đã đăng ký với SetUnhandledExceptionFilter(), chương trình sẽ tiếp tục thực thi chương trình tại địa chỉ được push vào đỉnh stack.  
còn đối với AddVectoredExceptionHandler, chương trình sẽ thoát sau khi thực thi hàm đã đăng ký.  

