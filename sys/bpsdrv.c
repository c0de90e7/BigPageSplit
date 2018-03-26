/*******************************************************************************************************************************************************************************************************
; BASE THEORY:
;
; We are going to transform this:
;
; CR3 ( PDBR, Page Directory Base Register )
;  __________________________________
; |                                  |
; | ppppppppppppppppppppffffffffffff |
; |__________ | _____________________|
;             |
;             |                          PD ( Page Directory )
;             v                           __________________________________
;   pppppppppppppppppppp000000000000 --->|                                  |
;                                        |                                  |
;                                        |__________________________________|
;                                        |                                  |
;                                        |                                  |
;                                        |__________________________________|
;                                        ~                                  ~
;                                        .                                  .
;                                        .                                  .
;                                        .                                  .
;                                        ~                                  ~     (1)
;                                        |                        ,-------------> G ( Global ) bit, normally set to 1 for big, 4MB pages
;                                        |                        |,------------> PS bit ( Page Size, 1 indicates those "p" refer to the physical address of a big, 4MB page. 0 indicates those "p" refere to the physical address of a Page Table )
;                                        |                        ||      ,-----> P bit ( Present, 1 indicates present. 0 indicates nonpresent )
;                                        |_______________________ || ____ | |
;                                        |                        vv      v |
;                                        | pppppppppprrrrrrrrrrfff11ffffff1 |                                          Big, 4MB page
;                                        |_____ | __________________________|     (2)                                   __________________________________
;                                        |      `-------------------------------> pppppppppp0000000000000000000000 --->|                                  |
;                                        |                                  |                                          |                                  |
;                                        ~                                  ~                                          |                                  |
;                                        .                                  .                                          |                                  |
;                                        .                                  .                                          |                                  |
;                                        .                                  .                                          |                                  |
;                                        ~                                  ~                                          |                                  |
;                                        |__________________________________|                                          |                                  |
;                                                                                                                      |                                  |
;                                                                                                                      ~                                  ~
;                                                                                                                      .                                  .
;                                                                                                                      .                                  .
;                                                                                                                      .                                  .
;                                                                                                                      ~                                  ~
;                                                                                                                      |__________________________________|
;
;
;
;
;
;
; Into this:
;
; CR3 ( PDBR, Page Directory Base Register )
;  __________________________________
; |                                  |
; | ppppppppppppppppppppffffffffffff |
; |__________ | _____________________|
;             |
;             |                          PD ( Page Directory )
;             v                           __________________________________
;   pppppppppppppppppppp000000000000 --->|                                  |
;                                        |                                  |
;                                        |__________________________________|
;                                        |                                  |
;                                        |                                  |
;                                        |__________________________________|
;                                        ~                                  ~
;                                        .                                  .
;                                        .                                  .
;                                        .                                  .
;                                        ~                                  ~     (4)
;                                        |                        ,-------------> G ( Global ) bit, we set it to 0 ( nonglobal ), although this bit is ignored for small, 4K pages
;                                        |                        |,------------> PS bit ( Page Size ), we set it to 0, so those "p" will be the physical address that will point to a Page Table
;                                        |                        ||      ,-----> P bit ( Present, 1 indicates present. 0 indicates nonpresent )
;                                        |_______________________ || ____ | |
;                                        |                        vv      v |
;                                        | ppppppppppppppppppppfff00ffffff1 |                                          previous 4MB page's physical memory
;                                        |_____ | __________________________|                                           __________________________________
;                                        |      `-------------------------------> pppppppppppppppppppp000000000000  .->|                                  |
;                                        |                                  |                       |               |  | First 4Ks: 00000000 to 00000FFF  |
;                                        ~                                  ~   (3)                 |               |  |__________________________________|
;                                        .                                  .   PT ( Page Table )   |               |.>|                                  |
;                                        .                                  .    ___________________v______________ || | Next 4ks:  00001000 to 00001FFF  |
;                                        .                                  .   |                                  ||| |__________________________________|
;                                        ~                                  ~   | pppppppppp0000000000fff00ffffff1 -'|>|                                  |
;                                        |__________________________________|   |__________________________________| ||| And so on: 00xxx000 to 00xxxFFF  |
;                                                                               |                                  | |||__________________________________|
;                                                                               | pppppppppp0000000001fff00ffffff1 --'|~                                  ~
;                                                                               |__________________________________|  |.                                  .
;                                                                               |                                  |  |.                                  .
;                                                                               | pppppppppp0000000010fff00ffffff1 ---'.                                  .
;                                                                               |__________________________________| .>~ Until:     003FF000 to 003FFFFF  ~
;                                                                               ~                                  ~ ||___________________________________|
;                                                                               .                                  . |
;                                                                               .                                  . |
;                                                                               .                                  . |
;                                                                               ~ pppppppppp1111111111fff00ffffff1 --'
;                                                                               |__________________________________|
;
;
; [1] This is the PDE ( Page Directory Entry ) that maps a 4MB page, normally ( always ? ) global, indicating PS==1 ( big, 4MB ) and present ( it could be otherwise,
;     but we aren't going to mess with nonpresent ones ). Those "p" bits are the first 10 bits ( MSB ) of the physical address of the pointed 4MB page. "r" bits are
;     reserved and "f" ones are flags. "1" flags indicate that "f" bit is set to 1. 
;
; [2] As said, those 10 "p" bits, plus 22 "0"s make the physical address of the 4MB page.  
;
; [3] This is a 4KB page we are going to allocate and fill with correct values ( nonpaged, contiguos and page boundary aligned ). This page will be used to create a
;     new Page Table for which we will set 1024 Page Table Entries which will map the entire original 4MB page on a 4K by 4K basis. For each of these Page Table Entries
;     we will respect original flags and upper 10 MSB of the physical address ( obvious ) and the remaining 10 physical address bits will get 0000000000 to 1111111111
;     values ( 00000 to 003FF ). So, one by one, 4K page by 4K page, these 1024 entries will map the original 4MB page again. 
;
; [4] After generating that new Page Table, we calculate its physical address, set G and PS bits to 0 ( non global, although it will be ignored for nonbig page PDEs;
;     nonbig page ). Then when we have prepared the new PDE, we can modify the existing one. This must me done atomically and for each process we find in the system,
;     since each process has its own page directory ( CR3 value ) so if we want the change to be global, we must change all processes.
;
;     Uhmmm... then... what about new processes ? Damn, we will need to change the desired PDE in each new process' page directory !? :(... No, we are lucky on this ;) 
;     Most of the time ( at least this was my case ), we will be wanting to do "page hooking" of global ( visible for all processes ) memory ranges. For example, I
;     was using this "hooking" for places into NTOSKRNL.EXE ( which, when the system has enough memory, is set up over a 4MB page ). Ok, so ? Well, when NTOSKRNL
;     creates a new process, when creating the process memory space, it allocates physical pages for the pages that are independent from other processes, but for pages
;     that are a) shared userspace ones or b) global for kernelsapce ( visible in all processes ) ones ( of course, there are some little exceptions to this... ), it
;     just picks the existing PDEs from the creator process ( the one who initiated the process creation ) and copies them to the newly created Page Directory:
;
;     Windows 2K SP0 ( Yes, I know, pretty old, but that's the machine I was using back then when experimenting with this :) ) NTOSKRNL.EXE:
;
;
;     ; When the execution reaches this point, EAX has the virtual address of the Page Directory Base that is just about to be created for describing new process' memory
;     ; address space
;
;     0043CF8F mov ecx,[0047F6ACh]      ; This is a global variable that holds the user-kernel barrier address minus 80000000h ( normally 0, but could be otherwise... )
;     0043CF95 add ecx,80000000h        ; it adds 80000000h so that ECX gets the value of the first kernelspace address
;     0043CF9B mov ebx,3FD00000h        ; 2s compliment of C0300000h ( This is the virtual address where the Page Directory gets mapped ) 
;     0043CFA0 mov esi,ecx              ; ESI will point to the PDEs that describe kernelspace into this, parent or CREATOR process. 
;     0043CFA2 shr esi,14h              ; This is a bit tricky, it takes 10 MSB of that virtual address by shifting out 20 LSB. 32-10 = 22, but since each PDE has 4 bytes
;     0043CFA5 shr ecx,16h              ; and it needs to scale the index by 4 in order to point into the Page Directory, it just shifts 20. Same for ECX but this time without scaling
;     0043CFA8 and esi,edx              ; EDX has a value of 00000FFCh which basically lets Directory Index scaled by 4 intact and clears all other bits
;     0043CFAA lea edi,[eax+ecx*4]      ; Make EDI point to the PDEs that describe kernelspace into the newly created child process' Page Directory
;     0043CFAD sub esi,ebx              ; This is like adding C0300000h ( i.e.: rebase ESI into the Page Directory of this CREATOR -parent- process )
;     0043CFAF mov ecx,00000080h        ; Copy 128 PDEs from parent process Page Directory to child process's Page Directory
;     0043CFB4 rep movsd                ; Copy Copy Copy ... 
;
;     ; NOTE: This 128 PDEs map a range of 128*4MB, 512 MB ( which, of course, can and do have gaps of nonpresent pages in between ). After this copying, other ranges
;     ;       are copied likewise, but these 128 are the ones that would more likely interest us :D
;
;     So, we see how the parent process' kernelspace PDEs of its Page Directory are used to create child process' kernelspace mapping. This could change in the future, although
;     I can see no reason for changing it and I think such a change is quite unlikely, but we never know... In such a changed scenario, in the worst case, a hook in every process  
;     creation will be needed ( we won't discuss possible places here, since there are too many places for doing it... ).
;
;
;
; NOTE: This scheme explains big page splits for non PAE mode. For PAE mode, page tables and its entries are different, but, in general, the same principles apply. Take a look at
;       intel's manuals and/or read through the code below and compare SplitBigPageNonPAEMode with SplitBigPagePAEMode.
;
*******************************************************************************************************************************************************************************************************/

#include "c:\winddk\3790.1830\inc\ifs\w2k\ntifs.h"

#include "bpsdrv.h"

extern PEPROCESS* PsInitialSystemProcess;
NTKERNELAPI KAFFINITY NTAPI KeSetAffinityThread(PKTHREAD Thread,KAFFINITY Affinity);

/*******************************************************************************
* Misc stuff for dealing with control registers and processor's features.      *
*******************************************************************************/

#define CR4_PSE ((ULONG)1<<4)
#define CR4_PAE ((ULONG)1<<5)
#define CR4_PGE ((ULONG)1<<7)

#define CPUID_01_EDX_PSE_SUPPORT ((ULONG)1<<3)
#define CPUID_01_EDX_PAE_SUPPORT ((ULONG)1<<6)
#define CPUID_01_EDX_PGE_SUPPORT ((ULONG)1<<13)

ULONG ReadCR4(void) // Returns current CR4's value
{
    ULONG CR4Value;

    __asm
    {
        _emit 0x0F  // mov eax,cr4  ; shitty asm compiler...
        _emit 0x20  //
        _emit 0xE0  //
        mov CR4Value,eax
    }
    
    return CR4Value;
}

void WriteCR4(ULONG CR4Value)   // Sets current CR4's value
{
    __asm
    {
        mov eax,CR4Value
        _emit 0x0F  // mov cr4,eax  ; shitty asm compiler...
        _emit 0x22  //
        _emit 0xE0  //
    }
}

ULONG ReadCR3(void) // Returns current CR3's value
{
    ULONG CR3Value;

    __asm
    {
        mov eax,cr3
        mov CR3Value,eax
    }
    
    return CR3Value;
}

void WriteCR3(ULONG CR3Value)   // Sets current CR3's value
{
    __asm
    {
        mov eax,CR3Value
        mov cr3,eax
    }
}

ULONG DoCPUID(ULONG EAXValue)   // Sets EAX's value to that found in EAXValue parameter, executes CPUID instruction and returns the resulting EDX register's value
{
    ULONG EDXValue;

    __asm
    {
        mov eax,EAXValue
        cpuid
        mov EDXValue,edx
    }
    
    return EDXValue;
}

int IsPSEEnabled(void)  // Returns TRUE if PSE feature is active on the processor, FALSE otherwise 
{
    ULONG CR4Register;
    ULONG EDXRegister;
 
    EDXRegister=DoCPUID(0x00000001);
    
    if(EDXRegister&CPUID_01_EDX_PSE_SUPPORT)
    {
        CR4Register=ReadCR4();

        return (CR4Register&CR4_PSE)?TRUE:FALSE;
    }
    else
    {
        return FALSE;
    }
}

int IsPAEEnabled(void)  // Returns TRUE if PAE feature is active on the processor, FALSE otherwise
{    
    ULONG CR4Register;
    ULONG EDXRegister;
 
    EDXRegister=DoCPUID(0x00000001);
    
    if(EDXRegister&CPUID_01_EDX_PAE_SUPPORT)
    {
        CR4Register=ReadCR4();

        return (CR4Register&CR4_PAE)?TRUE:FALSE;
    }
    else
    {
        return FALSE;
    }
}

int IsPGEEnabled(void)  // Returns TRUE if PGE feature is active on the processor, FALSE otherwise
{
    ULONG CR4Register;
    ULONG EDXRegister;
 
    EDXRegister=DoCPUID(0x00000001);
    
    if(EDXRegister&CPUID_01_EDX_PGE_SUPPORT)
    {
        CR4Register=ReadCR4();

        return (CR4Register&CR4_PGE)?TRUE:FALSE;
    }
    else
    {
        return FALSE;
    }
}

void ResetTLBOnAllProcessors(void)  // Resets TLB on all processors
{
    PETHREAD CurrentThread=PsGetCurrentThread();
    UCHAR i;

    if (IsPGEEnabled())
    {
        for(i=0;i<*KeNumberProcessors;i++)
        {
            KeSetAffinityThread(CurrentThread,1<<i);

            WriteCR4(ReadCR4()&(~CR4_PGE));
            WriteCR4(ReadCR4()|(CR4_PGE));
        }
    }
    else
    {
        for(i=0;i<*KeNumberProcessors;i++)
        {
            KeSetAffinityThread(CurrentThread,1<<i);

            WriteCR3(ReadCR3());
        }
    }
}

/*******************************************************************************
*******************************************************************************/

/*******************************************************************************
* Misc stuff for walking the active processes memory images.                   *
*******************************************************************************/

typedef struct _PROCESS_WALK_SCOPE  // Info block for process image walks, this acts as a "handle" for following functions 
{
    PEPROCESS CurrentProcess;
    ULONG InitialCR3;
    ULONG LastProcessCR3;
    ULONG CR3FieldDWORDIndex;
    ULONG NextFieldDWORDIndex;
}PROCESS_WALK_SCOPE,*PPROCESS_WALK_SCOPE;

int ProcessWalkFirst(PPROCESS_WALK_SCOPE ProcessWalkScope)  // Starts the process image walk. On exit, a return value of TRUE indicates the process image walk started successfully, ProcessWalkScope was initialized and processor's CR3 has been changed to map System process' memory image. 
{
    PULONG TempProcess;
    ULONG CurrentProcessId=(ULONG)PsGetCurrentProcessId(); 
    ULONG CR3Register;
    ULONG i;


    CR3Register=ReadCR3();

    ProcessWalkScope->InitialCR3=CR3Register;

    TempProcess=(PULONG)IoGetCurrentProcess();

    for(i=0;i<0x10;i++)
    {
        if(CR3Register==TempProcess[i])
        {
            ProcessWalkScope->CR3FieldDWORDIndex=i;

            break;
        }
    }

    if(0x10==i)
    {
        return FALSE;
    }

    for(i=0;i<0x40;i++)
    {
        if(CurrentProcessId==TempProcess[i])
        {
            ProcessWalkScope->NextFieldDWORDIndex=i+1;

            break;
        }
    }
    
    if(0x40==i)
    {
        return FALSE;
    }

    ProcessWalkScope->CurrentProcess=*PsInitialSystemProcess;

    TempProcess=(PULONG)ProcessWalkScope->CurrentProcess;
    
    CR3Register=TempProcess[ProcessWalkScope->CR3FieldDWORDIndex];

    WriteCR3(CR3Register);
    
    return TRUE;
}

int ProcessWalkNext(PPROCESS_WALK_SCOPE ProcessWalkScope)   // Advances process image walk to the next process image. On exit, a return value of TRUE indicates processor's CR3 has been changed to map the next process' memory image and that there are more processes to walk. FALSE indicates the walk has finished and processors CR3 has changed to map the memory image of the process who started the walk ( the initial one ).
{
    PULONG TempProcess;
    ULONG CR3Register;

    TempProcess=(PULONG)ProcessWalkScope->CurrentProcess;

    ProcessWalkScope->CurrentProcess=(PEPROCESS)((PUCHAR)TempProcess[ProcessWalkScope->NextFieldDWORDIndex]-(ProcessWalkScope->NextFieldDWORDIndex*sizeof(ULONG)));

    TempProcess=(PULONG)ProcessWalkScope->CurrentProcess;

    CR3Register=TempProcess[ProcessWalkScope->CR3FieldDWORDIndex];

    WriteCR3(CR3Register);

    if(CR3Register==ProcessWalkScope->InitialCR3)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/*******************************************************************************
*******************************************************************************/

/*******************************************************************************
* Functions for splitting big pages.                                           *
*******************************************************************************/

// // // NON-PAE MODE:

typedef struct _NON_PAE_MODE_LINEAR_ADDRESS // Representation of an IA-32 linear address in non PAE mode
{
    ULONG   OffsetIntoPage:12,
            PTIndex:10,
            PDIndex:10;
}NON_PAE_MODE_LINEAR_ADDRESS;

typedef union _NON_PAE_MODE_ADDRESS // Representation of an IA-32 virtual address in non PAE mode. This artifice lets us easily mix virtual addresses and linear addresses
{
    PVOID Address;
    NON_PAE_MODE_LINEAR_ADDRESS LinearAddress;
}NON_PAE_MODE_ADDRESS,*PNON_PAE_MODE_ADDRESS;

typedef struct _NON_PAE_MODE_BIG_PAGE_PDE   // Representation of a non PAE mode PDE for a big page
{
    ULONG   Present:1,
            ReadWrite:1,
            UserSupervisor:1,
            WriteThrough:1,
            CacheDisabled:1,
            Accessed:1,
            Dirty:1,
            PageSize:1,
            GlobalPage:1,
            Available:3,
            PageAttributeTableIndex:1,
            Reserved:9,
            PageBaseAddress:10;
}NON_PAE_MODE_BIG_PAGE_PDE,*PNON_PAE_MODE_BIG_PAGE_PDE;

typedef struct _NON_PAE_MODE_NON_BIG_PAGE_PDE   // Representation of a non PAE mode PDE for a small page
{
    ULONG   Present:1,
            ReadWrite:1,
            UserSupervisor:1,
            WriteThrough:1,
            CacheDisabled:1,
            Accessed:1,
            Reserved:1,
            PageSize:1,
            Ignored:1,
            Available:3,
            PageTableBaseAddress:20;
}NON_PAE_MODE_NON_BIG_PAGE_PDE,*PNON_PAE_MODE_NON_BIG_PAGE_PDE;

typedef union _NON_PAE_MODE_PDE // Generalization of both, big and small page PDE in non PAE mode
{
    NON_PAE_MODE_BIG_PAGE_PDE Big;
    NON_PAE_MODE_NON_BIG_PAGE_PDE NonBig;
}NON_PAE_MODE_PDE,*PNON_PAE_MODE_PDE;

typedef struct _NON_PAE_MODE_PTE    // Representation of a non PAE mode PTE
{
    ULONG   Present:1,
            ReadWrite:1,
            UserSupervisor:1,
            WriteThrough:1,
            CacheDisabled:1,
            Accessed:1,
            Dirty:1,
            PageAttributeTableIndex:1,
            GlobalPage:1,
            Available:3,
            PageBaseAddress:20;
}NON_PAE_MODE_PTE,*PNON_PAE_MODE_PTE;

void UpdateNonPAEModePDEInAllProcesses(PNON_PAE_MODE_PDE PDESlot,NON_PAE_MODE_PDE NewPDE)   // Sets the value of a PDE in every active process' paging structures ( non PAE mode, sets a PDE in the Page Directory of every process's memory image )
{
    PROCESS_WALK_SCOPE ProcessWalkScope;
    
    if(ProcessWalkFirst(&ProcessWalkScope))
    {
        do
        {
            *PDESlot=NewPDE;
        }
        while(ProcessWalkNext(&ProcessWalkScope));

        *PDESlot=NewPDE;
    }
}

int SplitBigPageNonPAEMode(PVOID VirtualAddressOfPage)  // Splits a big page ( changing its PDE and creating a new underlying PT ) into a set of small pages. Returns TRUE when success
{
    PNON_PAE_MODE_PDE NonPAEModePDEArray=(PNON_PAE_MODE_PDE)0xC0300000; // Virtual address where non PAE mode Page Directory gets mapped in NT
    PNON_PAE_MODE_PTE NonPAEModePTEArray=(PNON_PAE_MODE_PTE)0xC0000000; // Virtual address where non PAE mode Page Tables get mapped in NT

    NON_PAE_MODE_ADDRESS VirtualAddress;
    ULONG PDIndex;

    NON_PAE_MODE_PDE PDE;

    ULONG NewPageTablePDIndex;
    NON_PAE_MODE_PDE NewPageTablePDE;
    ULONG NewPageTablePTIndex;
    NON_PAE_MODE_PTE NewPageTablePTE;
    
    PNON_PAE_MODE_PTE NewPageTable;

    ULONG i;

    
    VirtualAddress.Address=VirtualAddressOfPage;    // We take the given address
    PDIndex=VirtualAddress.LinearAddress.PDIndex;   // and we take its linear address' PDIndex ( Page Directory Index )
    
    PDE=NonPAEModePDEArray[PDIndex];    // We take the PDE ( Page Directory Entry ) corresponding to the linear address by indexing the PDE array with PDIndex

    if((PDE.Big.Present)&&(PDE.Big.PageSize==1))    // Is the page present and is it a big page ?
    {   // The page is present and big size, so we try to split it
        NewPageTable=ExAllocatePoolWithTag(NonPagedPool,0x00001000,0);  // We allocate 4KB for a new page table we are going to generate

        if(NewPageTable)    // Allocation successful ?
        {   // Memory allocation for the new page table was successful, generate its PTE array
            for(i=0;i<0x00000400;i++)   // For every one of the 1024 entries on a non PAE mode PT ( Page Table )
            {   // Create a PTE with following field values
                NewPageTable[i].PageBaseAddress=(PDE.Big.PageBaseAddress<<10)|(i);  // Set its PageBaseAddress field to ( PageBaseAddress_field_of_the_to-be-splitted_page's_PDE * 1024 ) + i ( 0..1023 ). This is to make the 1024 PTEs alias the memory which the PDE defines
                NewPageTable[i].Available=PDE.Big.Available;    // Copy Available bits from the PDE we are aliasing
                NewPageTable[i].GlobalPage=0;   // Force G ( Global ) flag to be 0, we do not want to fuck the TLB, do we ?
                NewPageTable[i].PageAttributeTableIndex=0;
                NewPageTable[i].Dirty=PDE.Big.Dirty;                    // Copy the rest of the bits from the PDE we are aliasing
                NewPageTable[i].Accessed=PDE.Big.Accessed;              //
                NewPageTable[i].CacheDisabled=PDE.Big.CacheDisabled;    //
                NewPageTable[i].WriteThrough=PDE.Big.WriteThrough;      //
                NewPageTable[i].UserSupervisor=PDE.Big.UserSupervisor;  //
                NewPageTable[i].ReadWrite=PDE.Big.ReadWrite;            //
                NewPageTable[i].Present=PDE.Big.Present;                // this one could simply be NewPageTable[i].Present=1; ...
            }
    
            VirtualAddress.Address=NewPageTable;    // This is a bit tricky, we have generated a new PT ( Page Table ) and we are
                                                    // going to change the PDE that referes to the big page we are going to split
                                                    // so it indicates a size=1 ( small ) page and points to that generated PT.
                                                    // As the new PageTableBaseAddress field in the new PDE value is a physical
                                                    // address, we need to obtain the physical address of the generated PT.
            NewPageTablePDIndex=VirtualAddress.LinearAddress.PDIndex;   // We take its PDIndex...

            NewPageTablePDE.Big=NonPAEModePDEArray[NewPageTablePDIndex].Big;    // We take its PDE and we assume it is a big page

            // We will use this PDE as a template, just updating the needed flags, the other flags will be let as is
            if(NewPageTablePDE.Big.PageSize==1) // Is it a big page ?
            {   // Yes, generated PT is mapped over a big page, so we offset into that big page and generate a new PDE ( new value for the PDE that defines our to-be-splitted big page ) accordingly
                // Physical address bits are composed of 10 bits from the PageBaseAddress field of the PDE of the newly generated Page Table and the next 10 bits from the table index field into the virtual address of the newly
                // generated Page Table.
                NewPageTablePDE.NonBig.PageTableBaseAddress=(NewPageTablePDE.Big.PageBaseAddress<<10)|(VirtualAddress.LinearAddress.PTIndex);
                //  NewPageTablePDE.NonBig.Available:3      // let these flags as they are from the original PDE
                NewPageTablePDE.NonBig.Ignored=0;   // Force these to be 0
                NewPageTablePDE.NonBig.PageSize=0;  // small page...
                NewPageTablePDE.NonBig.Reserved=0;  //
                //  NewPageTablePDE.NonBig.Accessed:1       // let these flags as they are from the original PDE
                //  NewPageTablePDE.NonBig.CacheDisabled:1  //
                //  NewPageTablePDE.NonBig.WriteThrough:1   //
                //  NewPageTablePDE.NonBig.UserSupervisor:1 //
                //  NewPageTablePDE.NonBig.ReadWrite:1      //
                //  NewPageTablePDE.NonBig.Present:1        //
            }
            else
            {   // No, generated PT is mapped over a small page, so we use its physical address directly
                NewPageTablePTIndex=(VirtualAddress.LinearAddress.PDIndex<<10)|(VirtualAddress.LinearAddress.PTIndex);
                NewPageTablePTE=NonPAEModePTEArray[NewPageTablePTIndex];    // We take the physical address of the PTE of NewPageTable

                // Physical address bits are composed of 20 bits from the PageBaseAddress field of the PTE of the newly generated Page Table direcly
                NewPageTablePDE.NonBig.PageTableBaseAddress=NewPageTablePTE.PageBaseAddress;
                //  NewPageTablePDE.NonBig.Available:3      // let these flags as they are from the original PDE
                NewPageTablePDE.NonBig.Ignored=0;   // Force these to be 0
                NewPageTablePDE.NonBig.PageSize=0;  // small page...
                NewPageTablePDE.NonBig.Reserved=0;  //
                //  NewPageTablePDE.NonBig.Accessed:1       // let these flags as they are from the original PDE
                //  NewPageTablePDE.NonBig.CacheDisabled:1  //
                //  NewPageTablePDE.NonBig.WriteThrough:1   //
                //  NewPageTablePDE.NonBig.UserSupervisor:1 //
                //  NewPageTablePDE.NonBig.ReadWrite:1      //
                //  NewPageTablePDE.NonBig.Present:1        //
            }
            
            // Ok, at this point, we have a new value for tha big page PDE and we just need to set the new PDE into its corresponding slot in all processes' memory images
            UpdateNonPAEModePDEInAllProcesses(&NonPAEModePDEArray[PDIndex],NewPageTablePDE);
            
            return TRUE;    // We succeeded, return true to indicate we where able to split the big page into a set of small pages 
        }
        else
        {   // We could not allocate needed memory for creating a new PT ( Page Table ) so return FALSE to indicate we did not succeed
            return FALSE;
        }
    }
    else
    {   // The page was either non present or non big, so there is nothing to do, return FALSE to indicate we did not succeed
        return FALSE;
    }
}

// // // PAE MODE:

typedef struct _PAE_MODE_LINEAR_ADDRESS // Representation of an IA-32 linear address in PAE mode
{
    ULONG   OffsetIntoPage:12,
            PTIndex:9,
            PDIndex:11; // NOTE: This is not real, it should be PDIndex:9 and PDPTIndex:2 ( Page Directory Pointer Table Index ), but since NT maps all the PDs contiguosly, we treat these two indexes alltogether... 
}PAE_MODE_LINEAR_ADDRESS;

typedef union _PAE_MODE_ADDRESS // Representation of an IA-32 virtual address in PAE mode. This artifice lets us easily mix virtual addresses and linear addresses
{
    PVOID Address;
    PAE_MODE_LINEAR_ADDRESS LinearAddress;
}PAE_MODE_ADDRESS,*PPAE_MODE_ADDRESS;

typedef struct _PAE_MODE_BIG_PAGE_PDE   // Representation of a PAE mode PDE for a big page
{
    ULONG64 Present:1,
            ReadWrite:1,
            UserSupervisor:1,
            WriteThrough:1,
            CacheDisabled:1,
            Accessed:1,
            Dirty:1,
            PageSize:1,
            GlobalPage:1,
            Available:3,
            PageAttributeTableIndex:1,
            Reserved_:8,
            PageBaseAddress:15,
            Reserved:28;
}PAE_MODE_BIG_PAGE_PDE,*PPAE_MODE_BIG_PAGE_PDE;

typedef struct _PAE_MODE_NON_BIG_PAGE_PDE   // Representation of a PAE mode PDE for a small page
{
    ULONG64 Present:1,
            ReadWrite:1,
            UserSupervisor:1,
            WriteThrough:1,
            CacheDisabled:1,
            Accessed:1,
            Dirty:1,
            PageSize:1,
            Ignored:1,
            Available:3,
            PageTableBaseAddress:24,
            Reserved:28;
}PAE_MODE_NON_BIG_PAGE_PDE,*PPAE_MODE_NON_BIG_PAGE_PDE;

typedef union _PAE_MODE_PDE // Generalization of both, big and small page PDE in PAE mode
{
    PAE_MODE_BIG_PAGE_PDE Big;
    PAE_MODE_NON_BIG_PAGE_PDE NonBig;
}PAE_MODE_PDE,*PPAE_MODE_PDE;

typedef struct _PAE_MODE_PTE    // Representation of a PAE mode PTE
{
    ULONG64 Present:1,
            ReadWrite:1,
            UserSupervisor:1,
            WriteThrough:1,
            CacheDisabled:1,
            Accessed:1,
            Dirty:1,
            PageAttributeTableIndex:1,
            GlobalPage:1,
            Available:3,
            PageBaseAddress:24,
            Reserved:28;
}PAE_MODE_PTE,*PPAE_MODE_PTE;

void UpdatePAEModePDEInAllProcesses(PPAE_MODE_PDE PDESlot,PAE_MODE_PDE NewPDE)  // Sets the value of a PDE in every active process' paging structures ( PAE mode, sets a PDE in the Page Directory of every process's memory image )
{
    PROCESS_WALK_SCOPE ProcessWalkScope;
    
    if(ProcessWalkFirst(&ProcessWalkScope))
    {
        do
        {
            *PDESlot=NewPDE;    //  This would be better if we used an atomic 8 byte write... cmpxchg8b or some p3+ instruction...
        }
        while(ProcessWalkNext(&ProcessWalkScope));

        *PDESlot=NewPDE;
    }
}

int SplitBigPagePAEMode(PVOID VirtualAddressOfPage)  // Splits a big page ( changing its PDE and creating a new underlying PT ) into a set of small pages. Returns TRUE when success
{
    PPAE_MODE_PDE PAEModePDEArray=(PPAE_MODE_PDE)0xC0600000; // Virtual address where PAE mode Page Directory gets mapped in NT
    PPAE_MODE_PTE PAEModePTEArray=(PPAE_MODE_PTE)0xC0000000; // Virtual address where PAE mode Page Tables get mapped in NT

    PAE_MODE_ADDRESS VirtualAddress;
    ULONG PDIndex;

    PAE_MODE_PDE PDE;

    ULONG NewPageTablePDIndex;
    PAE_MODE_PDE NewPageTablePDE;
    ULONG NewPageTablePTIndex;
    PAE_MODE_PTE NewPageTablePTE;
    
    PPAE_MODE_PTE NewPageTable;

    ULONG i;

    
    VirtualAddress.Address=VirtualAddressOfPage;    // We take the given address
    PDIndex=VirtualAddress.LinearAddress.PDIndex;   // and we take its linear address' PDIndex ( Page Directory Index )
    
    PDE=PAEModePDEArray[PDIndex];    // We take the PDE ( Page Directory Entry ) corresponding to the linear address by indexing the PDE array with PDIndex

    if((PDE.Big.Present)&&(PDE.Big.PageSize==1))    // Is the page present and is it a big page ?
    {   // The page is present and big size, so we try to split it
        NewPageTable=ExAllocatePoolWithTag(NonPagedPool,0x00001000,0);  // We allocate 4KB for a new page table we are going to generate

        if(NewPageTable)    // Allocation successful ?
        {   // Memory allocation for the new page table was successful, generate its PTE array
            for(i=0;i<0x00000200;i++)   // For every one of the 512 entries on a PAE mode PT ( Page Table )
            {   // Create a PTE with following field values
                NewPageTable[i].Reserved=0; // Force these to be 0, they must be 0...
                NewPageTable[i].PageBaseAddress=(PDE.Big.PageBaseAddress<<9)|(i);  // Set its PageBaseAddress field to ( PageBaseAddress_field_of_the_to-be-splitted_page's_PDE * 512 ) + i ( 0..511 ). This is to make the 512 PTEs alias the memory which the PDE defines
                NewPageTable[i].Available=PDE.Big.Available;    // Copy Available bits from the PDE we are aliasing
                NewPageTable[i].GlobalPage=0;   // Force G ( Global ) flag to be 0, we do not want to fuck the TLB, do we ?
                NewPageTable[i].PageAttributeTableIndex=0;
                NewPageTable[i].Dirty=PDE.Big.Dirty;                    // Copy the rest of the bits from the PDE we are aliasing
                NewPageTable[i].Accessed=PDE.Big.Accessed;              //
                NewPageTable[i].CacheDisabled=PDE.Big.CacheDisabled;    //
                NewPageTable[i].WriteThrough=PDE.Big.WriteThrough;      //
                NewPageTable[i].UserSupervisor=PDE.Big.UserSupervisor;  //
                NewPageTable[i].ReadWrite=PDE.Big.ReadWrite;            //
                NewPageTable[i].Present=PDE.Big.Present;                // this one could simply be NewPageTable[i].Present=1; ...
            }
    
            VirtualAddress.Address=NewPageTable;    // This is a bit tricky, we have generated a new PT ( Page Table ) and we are
                                                    // going to change the PDE that referes to the big page we are going to split
                                                    // so it indicates a size=1 ( small ) page and points to that generated PT.
                                                    // As the new PageTableBaseAddress field in the new PDE value is a physical
                                                    // address, we need to obtain the physical address of the generated PT.
            NewPageTablePDIndex=VirtualAddress.LinearAddress.PDIndex;   // We take its PDIndex...

            NewPageTablePDE.Big=PAEModePDEArray[NewPageTablePDIndex].Big;    // We take its PDE and we assume it is a big page

            // We will use this PDE as a template, just updating the needed flags, the other flags will be let as is
            if(NewPageTablePDE.Big.PageSize==1) // Is it a big page ?
            {   // Yes, generated PT is mapped over a big page, so we offset into that big page and generate a new PDE ( new value for the PDE that defines our to-be-splitted big page ) accordingly
                NewPageTablePDE.NonBig.Reserved=0;  // Force these to be 0, they must be 0...
                // Physical address bits are composed of 15 bits from the PageBaseAddress field of the PDE of the newly generated Page Table and the next 9 bits from the table index field into the virtual address of the newly
                // generated Page Table.
                NewPageTablePDE.NonBig.PageTableBaseAddress=(NewPageTablePDE.Big.PageBaseAddress<<9)|(VirtualAddress.LinearAddress.PTIndex);
                //  NewPageTablePDE.NonBig.Available:3      // let these flags as they are from the original PDE
                NewPageTablePDE.NonBig.Ignored=0;   // Force these to be 0
                NewPageTablePDE.NonBig.PageSize=0;  // small page...;
                NewPageTablePDE.NonBig.Reserved=0;  //
                //  NewPageTablePDE.NonBig.Accessed:1       // let these flags as they are from the original PDE
                //  NewPageTablePDE.NonBig.CacheDisabled:1  //
                //  NewPageTablePDE.NonBig.WriteThrough:1   //
                //  NewPageTablePDE.NonBig.UserSupervisor:1 //
                //  NewPageTablePDE.NonBig.ReadWrite:1      //
                //  NewPageTablePDE.NonBig.Present:1        //
            }
            else
            {   // No, generated PT is mapped over a small page, so we use its physical address directly
                NewPageTablePTIndex=(VirtualAddress.LinearAddress.PDIndex<<9)|(VirtualAddress.LinearAddress.PTIndex);
                NewPageTablePTE=PAEModePTEArray[NewPageTablePTIndex];   // We take the physical address of the PTE of NewPageTable

                NewPageTablePDE.NonBig.Reserved=0;  // Force these to be 0, they must be 0...
                // Physical address bits are composed of 24 bits from the PageBaseAddress field of the PTE of the newly generated Page Table direcly
                NewPageTablePDE.NonBig.PageTableBaseAddress=NewPageTablePTE.PageBaseAddress;
                //  NewPageTablePDE.NonBig.Available:3      // let these flags as they are from the original PDE
                NewPageTablePDE.NonBig.Ignored=0;   // Force these to be 0
                NewPageTablePDE.NonBig.PageSize=0;  // small page...
                NewPageTablePDE.NonBig.Reserved=0;  //
                //  NewPageTablePDE.NonBig.Accessed:1       // let these flags as they are from the original PDE
                //  NewPageTablePDE.NonBig.CacheDisabled:1  //
                //  NewPageTablePDE.NonBig.WriteThrough:1   //
                //  NewPageTablePDE.NonBig.UserSupervisor:1 //
                //  NewPageTablePDE.NonBig.ReadWrite:1      //
                //  NewPageTablePDE.NonBig.Present:1        //
            }
                        
            // Ok, at this point, we have a new value for tha big page PDE and we just need to set the new PDE into its corresponding slot in all processes' memory images
            UpdatePAEModePDEInAllProcesses(&PAEModePDEArray[PDIndex],NewPageTablePDE);
            
            return TRUE;    // We succeeded, return true to indicate we where able to split the big page into a set of small pages 
        }
        else
        {   // We could not allocate needed memory for creating a new PT ( Page Table ) so return FALSE to indicate we did not succeed
            return FALSE;
        }
    }
    else
    {   // The page was either non present or non big, so there is nothing to do, return FALSE to indicate we did not succeed
        return FALSE;
    }
}

// // // BOTH, PAE and NON-PAE MODES:

int SplitBigPage(PVOID VirtualAddressOfPage)    // Splits the given page ( referenced by a virtual address that falls into the page ) into a set of small pages. Returns TRUE when success
{
    if(IsPSEEnabled())
    {   // If PSE is enabled, there is a chance that the given VirtualAddressOfPage refers to a Big ( 2MB or 4MB ) page, so we try to split it.
        if(IsPAEEnabled())
        {   // The system is using PAE paging mechanism, so we will try to split the 2MB page according to that mode.
            if(SplitBigPagePAEMode(VirtualAddressOfPage))
            {   // The given VirtualAddressOfPage was referring to a Big page and was splitted, we reset TLB on all processors.
                ResetTLBOnAllProcessors();

                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        else
        {   // The system is not using PAE paging mechanism, so we will try to split the 4MB page according to that mode.
            if(SplitBigPageNonPAEMode(VirtualAddressOfPage))
            {   // The given VirtualAddressOfPage was referring to a Big page and was splitted, we reset TLB on all processors.
                ResetTLBOnAllProcessors();

                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
    }
    else
    {   // If PSE is disabled or PSE feature is not present in the processor, there can not be Big ( 2MB or 4MB ) pages in the system, so there is nothing to do.
        return FALSE;
    }
}

/*******************************************************************************
*******************************************************************************/

void SplitNTOSKRNLModule(void)  // Split NTOSKRNL module's page(s)
{
    PUCHAR ArbitraryAddressIntoNTOSKRNL=(PUCHAR)PsInitialSystemProcess;

    if(IsPAEEnabled())
    {
        SplitBigPage(ArbitraryAddressIntoNTOSKRNL+0x00200000);  // This is a bit hackish or dirty... When I was playing around with
                                                                // PAE mode implementation of all this, I saw MmLockPagableSectionByHandle,
                                                                // MmUnlockPagableSectionByHandle and others related BSODed after performing
                                                                // the big page split. After a bit of reversing I found out what the cause
                                                                // was. These functions take a handle as a parameter ( ImageSectionHandle ).
                                                                // This handle refers to the address of a PE_IMAGE_SECTION_HEADER structure
                                                                // which references the section ( section of a module, as in PE executables )
                                                                // to be locked/unlocked. The problem comes when these functions assume that,
                                                                // if the section header ( passed in that parameter ) address is mapped over
                                                                // a small page, then the referenced section's memory range must also be
                                                                // mapped over a set of small pages. I do not know if this is a bug or not, I
                                                                // think it is an assumption based on some kind of internal convention that
                                                                // ensures modules are always mapped over the same type of pages. I have not
                                                                // done further research into this matter. In theory this is a problem in both
                                                                // PAE and non PAE modes, but it turns out to be a worse scenario in PAE mode.
                                                                // PAE mode big pages are 2MB size, and NTOSKRNL's memory takes two of these
                                                                // pages to get mapped. If we only split the page we need to split, we split
                                                                // the page which holds NTOSKRNL's image section headers ( which turn out to
                                                                // be used as handles for those BSODing functions ), but some sections ( one
                                                                // of them ) are mapped into the next 2MB page ( which we do not split ). So
                                                                // we split the page that holds the section headers but we let some of those
                                                                // referred sections memory range pages without splitting, and that's where
                                                                // we ruin it, the next time on of those functions is executed with a section
                                                                // header found in the page we split, a BSOD occurs. So, finally, the solution
                                                                // is to first split the section's memory range pages and then the original
                                                                // page we wanted to split ( which holds section's image section header ).
                                                                // We need to do it in this order: first the section's memory range and then
                                                                // the section's image section header, otherwise, since those functions are
                                                                // executed by ExAllocatePoolWithTag ( which we use ourselves ), we trigger
                                                                // the BSOD.
        SplitBigPage(ArbitraryAddressIntoNTOSKRNL);
    }
    else
    {
        SplitBigPage(ArbitraryAddressIntoNTOSKRNL);
    }
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
    Irp->IoStatus.Status=STATUS_SUCCESS;
    Irp->IoStatus.Information=0;
    
    IoCompleteRequest(Irp,IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

void Unload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Win32DeviceName;

    RtlInitUnicodeString(&Win32DeviceName,DOS_DEVICE_NAME);

    IoDeleteSymbolicLink(&Win32DeviceName);
    
    if (NULL!=DriverObject->DeviceObject)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
    PIO_STACK_LOCATION StackLocation;
    NTSTATUS NTStatus=STATUS_SUCCESS;
 
    StackLocation=IoGetCurrentIrpStackLocation(Irp);

    switch(StackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_DRIVER_METHOD_BUFFERED:
        //  DbgBreakPoint();

        SplitNTOSKRNLModule();
 
        // MmGetPhysicalMemoryRanges();

        break;

    default:
        NTStatus=STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status=NTStatus;

    IoCompleteRequest(Irp,IO_NO_INCREMENT);

    return NTStatus;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
    NTSTATUS NTStatus;
    UNICODE_STRING DeviceName;
    UNICODE_STRING Win32DeviceName;
    PDEVICE_OBJECT DeviceObject=NULL;

    RtlInitUnicodeString(&DeviceName,NT_DEVICE_NAME);
    
    NTStatus=IoCreateDevice(DriverObject,0,&DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&DeviceObject);

    if (!NT_SUCCESS(NTStatus))
    {
        return NTStatus;
    }
    
    DriverObject->MajorFunction[IRP_MJ_CREATE]=CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]=CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DeviceControl;
    DriverObject->DriverUnload=Unload;
   
    RtlInitUnicodeString(&Win32DeviceName,DOS_DEVICE_NAME);

    NTStatus=IoCreateSymbolicLink(&Win32DeviceName,&DeviceName);

    if (!NT_SUCCESS(NTStatus))
    {
        IoDeleteDevice(DeviceObject);
    }
    
    return NTStatus;
}
