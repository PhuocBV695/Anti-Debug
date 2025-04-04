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
## NtQueryInformationProcess()  
  
![image](https://github.com/user-attachments/assets/5b2b6ac0-ebc0-44f6-97e4-2c537d226f99)  
`PROCESSINFOCLASS` là một danh sách liệt kê chứa các giá trị xác định loại thông tin cần lấy từ một tiến trình  
một số giá trị cần chú ý:  
`ProcessDebugPort(0x7)`  
`ProcessDebugObjectHandle(0x1E)`  
`ProcessDebugFlags(0x1F)`  
### ProcessDebugPort  
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
còn khi không debug, chương trình sẽ chạy bình thường cho đến khi gặp ngoại lệ, sẽ thực thi hàm nUnhandledExceptionFilter() mà ta đã đăng ký.  
Khi debug:  

![image](https://github.com/user-attachments/assets/bf7313a1-7edf-46ac-9688-b9fc604a9fda)  
Khi không debug (hãy chú ý thứ tự thực thi):  

![image](https://github.com/user-attachments/assets/ee082fc7-94cb-44e7-adbc-b0f3771fca22)  
  
## RaiseException()  
  
code:  
```c
#include <stdio.h>
#include <Windows.h>

int main() {
    printf("hehe\n");
    __try {
        printf("haha\n");
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        printf("hihi\n");
        return 0;
    }
    __except (DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER // nếu ngoại lệ là DBG_CONTROL_C thì thực thi code bên trong except (tức "huhu")
        : EXCEPTION_CONTINUE_SEARCH) // còn khác thì tiếp tục thực thi code tiếp theo của ngoại lệ (tức "hihi")
    {   
        printf("huhu\n");
        return 0;
    }
}

```
cơ bản là RaiseException() đăng ký 1 ngoại lệ, nếu handler không xử lý được ngoại lệ thì sẽ tiếp tục chương trình, ngược lại thì sẽ báo exception  
```c
#include <stdio.h>
#include <Windows.h>

int main() {
    printf("hehe\n");
    RaiseException(DBG_CONTROL_C, 0, 0, NULL);
    printf("hihi\n");
    return 0;
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
Tức là khi không có debugger, chương trình chạy cho đến khi gặp ngoại lệ, sẽ nhảy vào hàm ExeptionHandler1() còn nếu ngoại lệ có thể xử lý được, sẽ chạy tiếp mà không nhảy vào hàm ExeptionHandler1()  
khi không debug:  
  
![image](https://github.com/user-attachments/assets/77b79592-44cb-4e24-88ea-687c17ef43ab)  
ta thấy chương trình đã thực hiện in "hehe" và khi gặp ngoại lệ, đã thực thi hàm ExeptionHandler1() thay vì tiếp tục hàm main()  
khi debug:  

![image](https://github.com/user-attachments/assets/1ec8ec8b-a1fc-4028-9a9e-cd02381a21a8)  
ta thấy chương trình không nhảy vào ExeptionHandler1() mà vẫn tiếp tục cho đến hết chương trình.  
  
Tuy có vẻ giống nhau nhưng ta cần phân biệt điểm khác nhau giữa AddVectoredExceptionHandler và SetUnhandledExceptionFilter():  
nhưng hàm được đăng ký với AddVectoredExceptionHandler có thể đăng ký thứ tự ưu tiên(khi gặp ngoại lệ) và có thể đăng ký nhiều hàm và sẽ được thực hiện theo thứ tự đăng ký, còn SetUnhandledExceptionFilter() có ưu tiên thấp nhất và sẽ bị ghi đè khi đăng ký nhiều lần  

## Bypass  
mục này có vẻ khá phức tạp và tiềm năng biến tấu thành những problem khó khá cao, việc patch, nop hay nhảy luồng chưa chắc đã tối ưu và đi được đúng hướng.  
# Timming  
Các kỹ thuật anti-debug mục này chủ yếu dựa vào sự chênh lệch thời gian hoặc số lượng câu lệnh  
## RDPMC/RDTSC  
Là 2 câu lệnh sử dụng cờ PCE trong thanh ghi CR4.  
RDPMC dùng trong Kernel mode.  
RDTSC dùng trong user mode.  
về cơ bản, 2 lệnh này có nhưng điểm phân biệt như sau:  
![image](https://github.com/user-attachments/assets/7acc26df-1d72-48cb-8643-9a56f092d4c8)  
code RDPMC:  
```c
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor  ecx, ecx
        rdpmc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... some work
    __asm
    {
        xor  ecx, ecx
        rdpmc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}
```
code RDTSC:  
```c
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // ... some work
    __asm
    {
        xor  ecx, ecx
        rdtsc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}
```
phần này vẫn là trả về `True` - `False` nên bypass không quá khó khăn và cũng dễ phát hiện.  
## GetLocalTime(), GetSystemTime()  
vẫn thế nhưng dùng localtime và gọi bằng WinApi thay vì dùng asm như trên  
code `GetLocalTime()`:  
```c
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    // ... some work
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
```  
code `GetSystemTime()`  
```c
bool IsDebugged(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetSystemTime(&stStart);
    // ... some work
    GetSystemTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
```
các cách anti-debug trong mục này cơ bản đều tương tự nhau, chỉ khác cách gọi hàm tính thời gian.  
# Process Memory  
## Breakpoints  
### Software Breakpoints (INT3)  
Kỹ thuật anti-debug này chỉ sử dụng được trong 1 vùng nhớ nhất định đã được khai báo trước  
nguyên lý là: khi debugger đặt breakpoint thì sẽ lưu opcode ở đấy rồi thay thế bằng 0xCC  
Để phát hiện thì chương trình kiểm tra vùng nhớ đấy xem có opcode 0xCC nào không  
code:  
```c
bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
{
    PBYTE pBytes = (PBYTE)pMemory; 
    for (SIZE_T i = 0; ; i++)
    {
        // Break on RET (0xC3) if we don't know the function's size
        if (((nMemorySize > 0) && (i >= nMemorySize)) ||
            ((nMemorySize == 0) && (pBytes[i] == 0xC3)))
            break;

        if (pBytes[i] == cByte)
            return true;
    }
    return false;
}

bool IsDebugged()
{
    PVOID functionsToCheck[] = {
        &Function1,
        &Function2,
        &Function3,
    };
    for (auto funcAddr : functionsToCheck)
    {
        if (CheckForSpecificByte(0xCC, funcAddr))
            return true;
    }
    return false;
}
```
cách bypass thì ta có thể patch đoạn code này hoặc đặt breakpoint ngay trước khi dòng code anti-debug này thực thi hoặc tryhard hơn thì đặt hardware breakpoint (vì hardware breakpoint không đặt opcode 0xcc)  
### Direct Memory Modification  
1 cách cực đoan hơn cách trên thì ta không chỉ quét opcodes 0xcc mà còn thay thế nó bằng opcodes khác như `nop`  
hoặc có thể là patch địa chỉ mà hàm return để thay đổi trực tiếp luồng chương trình, gây khó khăn cho việc debug  
code:  
```c
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

void foo()
{
    // ...
    
    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC) // int 3
    {
        DWORD dwOldProtect;
        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            *(PBYTE)pRetAddress = 0x90; // nop
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }
    
    // ...
}
```
### ReadFile(), WriteProcessMemory()  
vẫn hoạt động theo nguyên lý tnhuw trên nhưng dùng các WinApi như ReadFile(), WriteProcessMemory()  
### Hardware Breakpoints  
Hardware Breakpoint sử dụng Debug Registers (DR0 - DR3) để đặt breakpoint mà không thay đổi mã thực thi.  
CPU sẽ tự động dừng khi truy cập vào địa chỉ đã đặt mà không cần sửa đổi mã nguồn.  
để phát hiện thì chỉ cần kiểm tra các thanh ghi debug DR0, DR1, DR2, DR3, nếu có thanh ghi có giá trị khác 0 thì chương trình ấy đã bị đặt hardware breakpoint  
code:  
```c
bool IsDebugged()
{
    CONTEXT ctx;  // Tạo một cấu trúc CONTEXT để lưu trạng thái CPU
    ZeroMemory(&ctx, sizeof(CONTEXT));  // Đặt toàn bộ bộ nhớ của ctx thành 0
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;  // Chỉ lấy thông tin về Debug Registers

    if(!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
```
### Patch ntdll!DbgBreakPoint()  
kỹ thuật này khá hay  
Khi debugger cần đặt breakpoint, debugger sẽ phải gọi hàm `ntdll!DbgBreakPoint()`, chức năng của hàm này là thay thế opcodes tại breakpoint bằng exception `int 3`  
Kỹ thuật này anti-debug bằng cách patch luôn `ntdll!DbgBreakPoint()` khiến cho khi debugger đặt breakpoint, thay vì đặt 0xCC thì sẽ đặt 0xC3 `ret`  
muốn sử dụng lại chức năng đặt breakpoint thì phải khởi động lại hệ điều hành để ntdll.dll tạo lại process mới (phần này mình đã có nói ở bài shellcode)  
code:  
```c
void Patch_DbgBreakPoint()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return;

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
    if (!pDbgBreakPoint)
        return;

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;

    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // ret
}
```
### Performing Code Checksums  
Kỹ thuật này so sánh checksum của code gốc và code lúc debug, vì khi đặt breakpoint, ta đã thay đổi opcode nên checksum đã thay đổi, từ đó phát hiện debug  
code:  
```c
PVOID g_pFuncAddr;
DWORD g_dwFuncSize;
DWORD g_dwOriginalChecksum;

static void VeryImportantFunction()
{
    // ...
}

static DWORD WINAPI ThreadFuncCRC32(LPVOID lpThreadParameter)
{
    while (true)
    {
        if (CRC32((PBYTE)g_pFuncAddr, g_dwFuncSize) != g_dwOriginalChecksum)
            ExitProcess(0);
        Sleep(10000);
    }
    return 0;
}

size_t DetectFunctionSize(PVOID pFunc)
{
    PBYTE pMem = (PBYTE)pFunc;
    size_t nFuncSize = 0;
    do
    {
        ++nFuncSize;
    } while (*(pMem++) != 0xC3);
    return nFuncSize;
}

int main()
{
    g_pFuncAddr = (PVOID)&VeryImportantFunction;
    g_dwFuncSize = DetectFunctionSize(g_pFuncAddr);
    g_dwOriginalChecksum = CRC32((PBYTE)g_pFuncAddr, g_dwFuncSize);
    
    HANDLE hChecksumThread = CreateThread(NULL, NULL, ThreadFuncCRC32, NULL, NULL, NULL);
    
    // ...
    
    return 0;
}
```
# Assembly instructions  
## INT 3  
code:  
```c
bool IsDebugged()
{
    __try
    {
        __asm int 3;
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
```
debugger có thể xử lý exception `int 3` nên nếu ta`continue`, chương trình sẽ tiếp tục nhảy vào `return true` trước khi kịp vào `__except`  
từ đó chương trình có thể phát hiện debugger  
tương tự với `int 2d`  
## DebugBreak  
Tương tự `INT 3`/`INT 2D`, chỉ khác là được gọi từ WinApi thay vì asm  

