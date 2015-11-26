# Win32k-Fuzzer
****
credit to
https://twitter.com/R00tkitSMM (firozimaysam@gmail.com)
****
Win32k.sys for Windows  is like Java for internet.

this project have two part:

1. UAF detector  in Win32k
2. Win32k.sys fuzzer 

So i just publish First part

Win32k.sys for Windows  is like Java for internet.

in this days 0 day in kernel is more valuable than before because of limitation forced by sandboxes , every RCE Exploit need second phrase to bypass this Limitation to gain full system access.

many published local privilege escalation vulnerabilities is based  on Bug in Win32k and  how it handle/use Objects , in most vulnerabilities win32k use freed memory that lead to use after free vulnerabilities.

Win32 object allocation : 
based on Object type win32 with help of HMAllocObject function use heap or Pool for Allocating memory for object
```c++
int __stdcall HMAllocObject(int a1, PVOID Object, char a3, ULONG Size)
{
	....
	....

  if ( v5 & 0x10 && Object )
  {
    v7 = DesktopAlloc((int)Object, Size, ((unsigned __int8)a3 << 16) | 5);
    if ( !v7 )
    {
LABEL_28:
      UserSetLastError(8);
      return 0;
    }
    LockObjectAssignment(v7 + 12, Object);
    *(_DWORD *)(v7 + 16) = v7;
  }
  else
  {
    if ( v5 & 0x40 )
    {
      v8 = SharedAlloc(Size);
    }
    else
    {
      v9 = !Object && v5 & 0x20;
      if ( !(v5 & 8) || v9 )
        v8 = Win32AllocPoolWithTagZInit(Size, dword_BF9F191C[v4]);
      else
        v8 = Win32AllocPoolWithQuotaTagZInit(Size, dword_BF9F191C[v4]);
    }
    v7 = v8;
	....
	....
	....
	....
  }
  ````
  
1. DesktopAlloc ( Heap )
2. SharedAlloc ( heap )
3. in32AllocPoolWithQuotaTagZInit, Win32AllocPoolWithTagZInit (Pool )


for example Menu object use DesktopAlloc and Accelerator use Pool.

for objects that use Heap memory ,when object life end, OS call RtlFreeHeap to free used memory,after RtlFreeHeap return  freed memory still have ols/valid contents, so if other part of win32k.sys use freed memory nothing will happen because it use memory with old contents ( no BSOD ) and we will miss Bug.
until now researchers just find this kind of bugs with reverse engineering . they  must allocate object in same size to produce crash. and how know when OS will use freed memory ? 

in user mode  code we can  use gflags to enable page heap
```
gflags.exe /i iexplore.exe +hpa +ust to to enable the page heap (HPA)
```
we also can enable page heap system wide bug this dont effect Heap implementation in kernel 
thre was also "special pool" that can be enable with verifier but it dont help us for heap based objects/memory.


so my idea is patching RtlFreeHeap and fill freed memory with invalid content like 0c0c0c0c .
for finding heap chunk size i used unexported function RtlSizeHeap(thanks @ponez for finding this function)

```C++
__declspec(naked) my_function_detour_RtlFreeHeap()
{
	//PVOID  func=RtlSizeHeap;;
	__asm
	{		
		// exec missing instructions
		mov     edi,edi
		push    ebp
		mov     ebp,esp
		push    ebx
		mov     ebx,dword ptr [ebp+10h]
		int 3;
		/*
		BOOLEAN	RtlFreeHeap
		( 
		IN PVOID  HeapHandle,
		IN ULONG  Flags,
		IN PVOID  HeapBase
		); 
		mov     ebx,dword ptr [ebp+10h] get HeapBase  
		*/
		PUSHAD
		PUSH dword ptr [ebp+10h]
		PUSH dword ptr [ebp+0Ch]
		PUSH dword ptr [ebp+08h]
		call RtlSizeHeap;
		sub  ecx,ecx;
		mov ecx, eax; // size from RtlSizeHeap
		mov eax, 0x0c
		mov edi, ebx; // address of heap chunk
		rep stos byte ptr es:[edi]
		POPAD
````



with help of this function we can detect when win32k use freed heap memory.  we can also automatically find out how OS useing freed memory(does it use free memory to write/read/execute? )

i cheked this Detector with some old UAF vulnerabilities in Win32k and Driver detect UAF in win32k.sys.





