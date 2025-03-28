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
