#include<Ntifs.h>

PVOID RtlSizeHeap;
static UCHAR RtlSizeHeapSign[]=
{
0x8b, 0xff, 0x55, 0x8b, 0xec, 0x8b, 0x4d, 0x10, 0x53, 0x56, 0x8b, 0x75, 0x08, 0x33,
0xdb, 0xf6, 0x46, 0x48, 0x01, 0x75, 0x34, 0xf6, 0xc1, 0x07, 0x75, 0x20, 0x8d, 0x41,
0xf8, 0x80, 0x78, 0x07, 0x05, 0x75, 0x09, 0x0f, 0xb6, 0x48, 0x06, 0xc1, 0xe1, 0x03, 
0x2b, 0xc1, 0xf6, 0x40, 0x07, 0x3f, 0x75, 0x1e, 0x53, 0x53, 0x6a, 0x08, 0x8b, 0xc8,
};

#pragma pack(push, 1)
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11

} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_MODULE_INFORMATION   // Information Class 11
{
    ULONG Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];

} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


NTSTATUS
NTAPI
ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                         IN OUT PVOID SystemInformation,
                         IN ULONG SystemInformationLength,
                         OUT PULONG ReturnLength OPTIONAL);

#pragma pack(pop)


NTSTATUS CheckFunctionBytesRtlFreeHeap()
{
	int i=0;
	char *p = (char *)RtlFreeHeap;

	/*
	nt!RtlFreeHeap:
	817155a3 8bff            mov     edi,edi
	817155a5 55              push    ebp
	817155a6 8bec            mov     ebp,esp
	817155a8 53              push    ebx
	817155a9 8b5d10          mov     ebx,dword ptr [ebp+10h]
	817155ac 56              push    esi
	817155ad 33f6            xor     esi,esi
	817155af 57              push    edi
	817155b0 3bde            cmp     ebx,esi
	*/
	
	char c[] = { 0x8b, 0xff, 0x55, 0x8b, 0xec, 0x53, 0x8b, 0x5D, 0x10 };
	
	while(i<9)
	{
		DbgPrint(" - 0x%02X ", (unsigned char)p[i]);
		if(p[i] != c[i])
		{
			return STATUS_UNSUCCESSFUL; 
		}
		i++;
	}
	return STATUS_SUCCESS;
}

// naked functions have no prolog/epilog code - they are functionally like the 
// target of a goto statement
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
		mov eax, 0x1
		mov edi, ebx; // address of heap chunk
		rep stos byte ptr es:[edi]
		POPAD
		
		// jump to re-entry location in hooked function
		// this gets 'stamped' with the correct address
		// at runtime.
		//
		// we need to hard-code a far jmp, but the assembler
		// that comes with the DDK will not poop this out
		// for us, so we code it manually
		// jmp FAR 0x08:0xAAAAAAAA
		_emit 0xEA
		_emit 0xAA
		_emit 0xAA
		_emit 0xAA
		_emit 0xAA
		_emit 0x08
		_emit 0x00
	}
}


VOID DetourFunctionRtlFreeHeap()
{
	char *actual_function = (char *)RtlFreeHeap;
	char *non_paged_memory;
	unsigned long detour_address;
	unsigned long reentry_address;
	int i = 0;

	// assembles to jmp far 0008:11223344 where 11223344 is address of
	// our detour function, plus two NOP's to align up the patch
	char newcode[] = { 0xEA, 0x44, 0x33, 0x22, 0x11, 0x08, 0x00, 0x90, 0x90 };

	// reenter the hooked function at a location past the overwritten opcodes
	// alignment is, of course, very important here
	reentry_address = ((unsigned long)RtlFreeHeap) + 9; 

	non_paged_memory = ExAllocatePool(NonPagedPool, 256);
	
	// copy contents of our function into non paged memory
	// with a cap at 256 bytes (beware of possible read off end of page FIXME)
	for(i=0;i<256;i++)
	{
		((unsigned char *)non_paged_memory)[i] = ((unsigned char *)my_function_detour_RtlFreeHeap)[i];
	}

	detour_address = (unsigned long)non_paged_memory;
	
	// stamp in the target address of the far jmp
	*( (unsigned long *)(&newcode[1]) ) = detour_address;

	// now, stamp in the return jmp into our detour
	// function
	for(i=0;i<200;i++)
	{
		if( (0xAA == ((unsigned char *)non_paged_memory)[i]) &&
			(0xAA == ((unsigned char *)non_paged_memory)[i+1]) &&
			(0xAA == ((unsigned char *)non_paged_memory)[i+2]) &&
			(0xAA == ((unsigned char *)non_paged_memory)[i+3]))
		{
			// we found the address 0xAAAAAAAA
			// stamp it w/ the correct address
			*( (unsigned long *)(&non_paged_memory[i]) ) = reentry_address;
			break;
		}
	}

	//TODO, raise IRQL

	//overwrite the bytes in the kernel function
	//to apply the detour jmp
	for(i=0;i < 9;i++)
	{
		actual_function[i] = newcode[i];
	}

	//TODO, drop IRQL
}

VOID UnDetourFunction()
{
	//TODO!
}

VOID OnUnload( IN PDRIVER_OBJECT DriverObject )
{
	DbgPrint("My Driver Unloaded!");

	UnDetourFunction();
}


NTSTATUS RtlGetModuleBase(IN LPCSTR     pszModuleName,OUT PVOID*    ppBaseAddress,int* sizeofimage)
{
    NTSTATUS                    nts, ntsInternal;
    ULONG                       ulLength;
    PSYSTEM_MODULE_INFORMATION  pModuleInfo;
    PVOID                       pBuffer = NULL;

    __try
    {

        nts = ZwQuerySystemInformation(SystemModuleInformation,
                                       &ulLength,
                                       0,
                                       &ulLength);

        if (nts != STATUS_INFO_LENGTH_MISMATCH)
        {
            ASSERT(FALSE);
            return nts;
        }

     
        if (!(pBuffer = ExAllocatePool(PagedPool, ulLength)))
        {
            ASSERT(FALSE);
            return STATUS_NO_MEMORY;
        }

     
        nts = ZwQuerySystemInformation(SystemModuleInformation,
                                       pBuffer,
                                       ulLength,
                                       &ulLength);
        if (NT_SUCCESS(nts))
        {
            nts = STATUS_OBJECT_NAME_NOT_FOUND;

    
            ulLength = *(PULONG)pBuffer;
            pModuleInfo = (PSYSTEM_MODULE_INFORMATION)((PULONG)pBuffer + 1);

            while(ulLength--)
            {

                if (!_stricmp(&pModuleInfo[ulLength].ImageName[pModuleInfo[ulLength].ModuleNameOffset],pszModuleName))
                {
              
                    *ppBaseAddress = pModuleInfo[ulLength].Base;
					*sizeofimage= pModuleInfo[ulLength].Size;
                    nts = STATUS_SUCCESS;
                    break;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {

        ASSERT(FALSE);
        nts = GetExceptionCode();
    }


    if (pBuffer)
        ExFreePool(pBuffer);

    return nts;
}


PVOID ScanForRtlSizeHeap(ULONG_PTR StartAddress, int ScanLength )
{
	PUCHAR bytes;
    PCHAR endAddress;
    PCHAR address;

    endAddress =(PCHAR)(StartAddress + ScanLength);	
	for (address =(PCHAR) StartAddress; address < endAddress; address++)
	{
        if (RtlCompareMemory((PVOID)address, RtlSizeHeapSign, sizeof(RtlSizeHeapSign)) == sizeof(RtlSizeHeapSign))
        {
			DbgBreakPoint();
            return  (PVOID)(address);
        }
	}
	return NULL;
}


/*


SIZE_T
RtlSizeHeap (
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress
    )
	
*/

NTSTATUS DriverEntry( IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath )
{
	NTSTATUS	nts;
	PVOID       pBaseAddress=NULL;
	int Sizeofimage=0;
	
	
	
	DbgPrint("My Driver Loaded!");
	DbgBreakPoint();
	nts = RtlGetModuleBase("ntkrnlpa.exe",&pBaseAddress,&Sizeofimage);
	
    if (!NT_SUCCESS(nts))
        return nts;
	
	RtlSizeHeap=NULL;
	RtlSizeHeap=ScanForRtlSizeHeap((ULONG_PTR)pBaseAddress,Sizeofimage);
	
	if(!RtlSizeHeap)return STATUS_UNSUCCESSFUL;
	
	DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"pBaseAddress %x , Sizeofimage %x, RtlSizeHeap %x \r\n",pBaseAddress,Sizeofimage,RtlSizeHeap);

	if(STATUS_SUCCESS != CheckFunctionBytesRtlFreeHeap())
	{
		DbgPrint("Match Failure on RtlFreeHeap!");
		return STATUS_UNSUCCESSFUL;
	}
	
	DetourFunctionRtlFreeHeap();

	return STATUS_SUCCESS;
}
