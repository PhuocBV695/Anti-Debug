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

    HANDLE DebugObject = NULL;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x1e, &DebugObject, sizeof(HANDLE), NULL);

    if (status == 0 && DebugObject) {
        printf("Process is being debugged!\n");
    } else {
        printf("Process is not being debugged.\n");
    }

    return 0;
}


```
về ProcessDebugObjectHandle và ProcessDebugFlags, cơ chế khác với ProcessDebugPort, tuy nhiên cách viết code anti-debug cũng tương tự, chỉ thay 0x07 thành 0x1e hoặc 0x1f  
# Object Handles  
