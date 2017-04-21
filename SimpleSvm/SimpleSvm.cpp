/*!
    @file       SimpleSvm.cpp

    @brief      TBD.

    @author     Satoshi Tanda

    @copyright  Copyright (c) 2017, Satoshi Tanda. All rights reserved.
 */
#include "SimpleSvm.hpp"

#include <intrin.h>
#include <ntifs.h>
#include <stdarg.h>
#include <ntstrsafe.h>

EXTERN_C DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverUnload;

EXTERN_C
VOID
_sgdt (
    _Out_ PVOID Descriptor
    );

_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
DECLSPEC_NORETURN
EXTERN_C
VOID
NTAPI
SvLaunchVm (
    _In_ PVOID HostRsp
    );

typedef struct _PML4_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;               // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Reserved1 : 3;           // [6:8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 PageFrameNumber : 40;    // [12:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PML4_ENTRY_2MB, *PPML4_ENTRY_2MB,
  PDP_ENTRY_2MB, *PPDP_ENTRY_2MB;
static_assert(sizeof(PML4_ENTRY_2MB) == 8,
              "PML4_ENTRY_1GB Size Mismatch");

typedef struct _PD_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;               // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Dirty : 1;               // [6]
            UINT64 LargePage : 1;           // [7]
            UINT64 Global : 1;              // [8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 Pat : 1;                 // [12]
            UINT64 Reserved1 : 8;           // [13:20]
            UINT64 PageFrameNumber : 31;    // [21:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PD_ENTRY_2MB, *PPD_ENTRY_2MB;
static_assert(sizeof(PD_ENTRY_2MB) == 8,
              "PDE_ENTRY_2MB Size Mismatch");

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA
{
    DECLSPEC_ALIGN(PAGE_SIZE) PML4_ENTRY_2MB Pml4Entries[1];    // just for 512 GB
    DECLSPEC_ALIGN(PAGE_SIZE) PDP_ENTRY_2MB PdpEntries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PD_ENTRY_2MB PdeEntries[512][512];
} SHARED_VIRTUAL_PROCESSOR_DATA, *PSHARED_VIRTUAL_PROCESSOR_DATA;

typedef struct _VIRTUAL_PROCESSOR_DATA
{
    union
    {
        /*
            Low     ShvStackLimit[0]                        StackLimit
            ^       ...
            ^       ShvStackLimit[KERNEL_STACK_SIZE - 2]    StackBase
            High    ShvStackLimit[KERNEL_STACK_SIZE - 1]    StackBase
        */
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 ShvStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            UINT8 StackContents[KERNEL_STACK_SIZE - sizeof(PVOID) * 6];
            UINT64 GuestVmcbPa;
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA *Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData;
            UINT64 Padding1;
            UINT64 Reserved1;
        } HostStackLayout;
    };

    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
} VIRTUAL_PROCESSOR_DATA, *PVIRTUAL_PROCESSOR_DATA;
static_assert(sizeof(VIRTUAL_PROCESSOR_DATA) == KERNEL_STACK_SIZE + PAGE_SIZE * 3,
              "VIRTUAL_PROCESSOR_DATA Size Mismatch");

typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rsp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS, *PGUEST_REGISTERS;

typedef struct _GUEST_CONTEXT
{
    PGUEST_REGISTERS VpRegs;
    BOOLEAN ExitVm;
} GUEST_CONTEXT, *PGUEST_CONTEXT;

#include <pshpack1.h>
typedef struct _DESCRIPTOR
{
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR, *PDESCRIPTOR;
static_assert(sizeof(DESCRIPTOR) == 10,
              "DESCRIPTOR Size Mismatch");
#include <poppack.h>

typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT16 LimitLow;        // [0:15]
            UINT16 BaseLow;         // [16:31]
            UINT32 BaseMiddle : 8;  // [32:39]
            UINT32 Type : 4;        // [40:43]
            UINT32 System : 1;      // [44]
            UINT32 Dpl : 2;         // [45:46]
            UINT32 Present : 1;     // [47]
            UINT32 LimitHigh : 4;   // [48:51]
            UINT32 Avl : 1;         // [52]
            UINT32 LongMode : 1;    // [53]
            UINT32 DefaultBit : 1;  // [54]
            UINT32 Granularity : 1; // [55]
            UINT32 BaseHigh : 8;    // [56:63]
        } Fields;
    };
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;
static_assert(sizeof(SEGMENT_DESCRIPTOR) == 8,
              "SEGMENT_DESCRIPTOR Size Mismatch");

typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;        // [0:3]
            UINT16 System : 1;      // [4]
            UINT16 Dpl : 2;         // [5:6]
            UINT16 Present : 1;     // [7]
            UINT16 Avl : 1;         // [8]
            UINT16 LongMode : 1;    // [9]
            UINT16 DefaultBit : 1;  // [10]
            UINT16 Granularity : 1; // [11]
            UINT16 Reserved1 : 4;   // [12:15]
        } Fields;
    };
} SEGMENT_ATTRIBUTE, *PSEGMENT_ATTRIBUTE;
static_assert(sizeof(SEGMENT_ATTRIBUTE) == 2,
              "SEGMENT_ATTRIBUTE Size Mismatch");

#define IA32_MSR_VM_CR 0xc0010114   // See: VM_CR MSR (C001_0114h)
#define IA32_MSR_EFER 0xc0000080
#define IA32_MSR_VM_HSAVE_PA 0xc0010117
#define IA32_MSR_PAT 0x00000277

#define VM_CR_SVMDIS (1UL << 4)
#define EFER_SVME (1UL << 12)  // See: Extended Feature Enable Register (EFER)
#define CPUID_FN8000_0001_ECX_SVM   (1ul << 2)  // See: CPUID Fn8000_0001_ECX Feature Identifiers
#define CPUID_FN8000_000A_EDX_NP    (1ul << 0)  // See: CPUID Fn8000_000A_EDX SVM Feature Identification
#define CPUID_FN8000_000A_EDX_DECODE_ASSISTS    (1ul << 7)

// See: Function 0h—Maximum Standard Function Number and Vendor String
#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING      0
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS   1
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT  (1UL << 31)

#define MAKEULONGLONG(lo,hi) ((ULONGLONG)lo + ((ULONGLONG)hi << 32))

//
// http://lxr.free-electrons.com/source/arch/x86/include/uapi/asm/hyperv.h
//
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define HYPERV_CPUID_INTERFACE                  0x40000001
#define HYPERV_CPUID_MAX                        HYPERV_CPUID_INTERFACE

#define HYPERV_HYPERVISOR_PRESENT_BIT           0x80000000
#define HYPERV_CPUID_MIN                        0x40000005

#define RPL_MASK                3
#define DPL_SYSTEM              0

#define SV_CPUID_UNLOAD_SIMPLESVM               0x41414141


/*!
    @brief      Breaks into a kernel debugger when it is present.

    @details    This macro is emits software breakpoint that only hits when a
                kernel debugger is present. This macro is useful because it does
                not change the current frame unlike the DbgBreakPoint function,
                and breakpoint by this macro can be overwritten with NOP without
                impacting other breakpoints.
 */
#define SV_DEBUG_BREAK() \
    if (KD_DEBUGGER_NOT_PRESENT) \
    { \
        NOTHING; \
    } \
    else \
    { \
        __debugbreak(); \
    } \
    reinterpret_cast<void*>(0)

/*!
    @brief      Sends a message to the kernel debugger.

    @param[in]  Format - The format string to print.
    @param[in]  arguments - Arguments for the format string, as in printf.
 */
_IRQL_requires_same_
static
VOID
SvDebugPrint (
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    static const UINT32 MAX_FORMAT_LENGTH = 1024;
    NTSTATUS status;
    CHAR extendedFormat[MAX_FORMAT_LENGTH];
    LPCCH finalFormat;
    va_list arglist;

    status = RtlStringCchPrintfA(
                extendedFormat,
                RTL_NUMBER_OF(extendedFormat),
                "[SimpleSvm] #%lu %5Iu %5Iu %s\n",
                KeGetCurrentProcessorNumberEx(nullptr),
                reinterpret_cast<ULONG_PTR>(PsGetProcessId(PsGetCurrentProcess())),
                reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()),
                Format);
    if (!NT_SUCCESS(status))
    {
        finalFormat = Format;
        goto Exit;
    }

    finalFormat = extendedFormat;

Exit:
    va_start(arglist, Format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, finalFormat, arglist);
    va_end(arglist);
}

/*!
    @brief      TBD.

    @details    TBD.

    @param[in]  TBD - TBD.

    @result     STATUS_SUCCESS on success, or an appropriate error code.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
static
PVOID
SvAllocatePageAlingedPhysicalMemory (
    _In_ SIZE_T NumberOfBytes
    )
{
    PVOID memory;

    NT_ASSERT(NumberOfBytes >= PAGE_SIZE);

    memory = ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, 'MVSS');
    if (memory != nullptr)
    {
        NT_ASSERT(PAGE_ALIGN(memory) == memory);
        RtlZeroMemory(memory, NumberOfBytes);
    }
    return memory;
}

/*!
    @brief      Frees memory allocated by SvAllocatePageAlingedPhysicalMemory.

    @param[in]  BaseAddress - The address returned by SvAllocatePageAlingedPhysicalMemory.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
SvFreePageAlingedPhysicalMemory (
    _In_ PVOID BaseAddress
    )
{
    ExFreePoolWithTag(BaseAddress, 'MVSS');
}

/*!
    @brief      TBD.

    @details    TBD.

    @param[in]  TBD - TBD.
 */
_IRQL_requires_same_
static
VOID
SvHandleCpuid (
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PGUEST_CONTEXT GuestContext
    )
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    int leaf;
    int subLeaf;
    SEGMENT_ATTRIBUTE attribute;

    UNREFERENCED_PARAMETER(VpData);

    leaf = static_cast<int>(GuestContext->VpRegs->Rax);
    subLeaf = static_cast<int>(GuestContext->VpRegs->Rcx);

    __cpuidex(registers, leaf, subLeaf);

    switch (leaf)
    {
    case CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS:
        registers[3] |= CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT;
        break;
    case HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS:
        registers[0] = HYPERV_CPUID_MAX;
        registers[1] = 'pmiS';  // "SimpleSvm   "
        registers[2] = 'vSel';
        registers[3] = '   m';
        break;
    case HYPERV_CPUID_INTERFACE:
        registers[0] = '0#vH';  // Hv#0
        registers[1] = registers[2] = registers[3] = 0;
        break;
    case SV_CPUID_UNLOAD_SIMPLESVM:
        if (subLeaf == SV_CPUID_UNLOAD_SIMPLESVM)
        {
            attribute.AsUInt16 = VpData->GuestVmcb.StateSaveArea.SsAttrib;
            if (attribute.Fields.Dpl == DPL_SYSTEM)
            {
                GuestContext->ExitVm = TRUE;
            }
            break;
        }
    default:
        break;
    }

    GuestContext->VpRegs->Rax = registers[0];
    GuestContext->VpRegs->Rbx = registers[1];
    GuestContext->VpRegs->Rcx = registers[2];
    GuestContext->VpRegs->Rdx = registers[3];

    if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
    {
        SvDebugPrint("CPUID: %08x-%08x : %08x %08x %08x %08x",
                               leaf,
                               subLeaf,
                               registers[0],
                               registers[1],
                               registers[2],
                               registers[3]);
    }

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

/*!
    @brief      TBD.

    @details    TBD.

    @param[in]  TBD - TBD.

    @result     STATUS_SUCCESS on success, or an appropriate error code.
 */
_IRQL_requires_same_
EXTERN_C
BOOLEAN
NTAPI
SvHandleVmExit (
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PGUEST_REGISTERS GuestRegisters
    )
{
    GUEST_CONTEXT guestContext;

    //SV_DEBUG_BREAK();

    //;
    //; Set the global interrupt flag again, but execute cli to make sure IF=0.
    //;
    _disable();
    __svm_stgi();
    __svm_vmload(VpData->HostStackLayout.HostVmcbPa);

    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);

    guestContext.VpRegs = GuestRegisters;
    guestContext.VpRegs->Rax = VpData->GuestVmcb.StateSaveArea.Rax;
    guestContext.ExitVm = FALSE;


    switch (VpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_CPUID:
        SvHandleCpuid(VpData, &guestContext);
        break;
    default:
        SV_DEBUG_BREAK();
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

    if (guestContext.ExitVm != FALSE)
    {
        guestContext.VpRegs->Rax = VpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = reinterpret_cast<UINT_PTR>(VpData) >> 32;
        guestContext.VpRegs->Rdx = reinterpret_cast<UINT_PTR>(VpData) & MAXUINT32;

        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);
        __svm_stgi();

        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);
        _enable();
        goto Exit;
    }

    NT_ASSERT((VpData->GuestVmcb.StateSaveArea.Efer & EFER_SVME) != 0);
    VpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;

    __svm_clgi();
    _enable();

Exit:
    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);
    return guestContext.ExitVm;
}

/*!
    @brief      TBD.

    @details    TBD.

    @param[in]  TBD - TBD.

    @result     STATUS_SUCCESS on success, or an appropriate error code.
 */
_IRQL_requires_same_
_Check_return_
static
UINT16
SvGetSegmentAccessRight (
    _In_ UINT16 SegmentSelector,
    _In_ ULONG_PTR GdtBase
    )
{
    PSEGMENT_DESCRIPTOR descriptor;
    SEGMENT_ATTRIBUTE attribute;

    descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
                                        GdtBase + (SegmentSelector & ~RPL_MASK));

    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}

/*!
    @brief      TBD.

    @details    TBD.

    @param[in]  TBD - TBD.

    @result     STATUS_SUCCESS on success, or an appropriate error code.
 */
//
// See: Requirements for implementing the Microsoft Hypervisor interface
// https://msdn.microsoft.com/en-us/library/windows/hardware/Dn613994(v=vs.85).aspx
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
BOOLEAN
SvIsSimpleSvmInstalled (
    VOID
    )
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    char vendorId[13];

    __cpuid(registers, HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS);
    RtlCopyMemory(vendorId + 0, &registers[1], sizeof(registers[1]));
    RtlCopyMemory(vendorId + 4, &registers[2], sizeof(registers[2]));
    RtlCopyMemory(vendorId + 8, &registers[3], sizeof(registers[3]));
    vendorId[12] = ANSI_NULL;

    return (strcmp(vendorId, "SimpleSvm   ") == 0);
}

static
VOID
SvPrepareForVirtualization (
    PVIRTUAL_PROCESSOR_DATA vpData,
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData,
    PCONTEXT Context
    )
{
    DESCRIPTOR currentGdtr, currentIdtr;
    PHYSICAL_ADDRESS guestVmcbPa, hostVmcbPa, hostStateAreaPa, pml4BasePa;

    _sgdt(&currentGdtr);
    __sidt(&currentIdtr);

    guestVmcbPa = MmGetPhysicalAddress(&vpData->GuestVmcb);
    hostVmcbPa = MmGetPhysicalAddress(&vpData->HostVmcb);
    hostStateAreaPa = MmGetPhysicalAddress(&vpData->HostStateArea);
    pml4BasePa = MmGetPhysicalAddress(&sharedVpData->Pml4Entries);

    //
    // Save guest state to VMCB.
    //
    __svm_vmsave(guestVmcbPa.QuadPart);

    // EFER.SVME defaults to a reset
    // value of zero. The effect of turning off EFER.SVME while a guest is running is undefined; therefore,
    // the VMM should always prevent guests from writing EFER.

    vpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    vpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;
    vpData->GuestVmcb.ControlArea.GuestAsid = 1;
    vpData->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    vpData->GuestVmcb.ControlArea.NCr3 = pml4BasePa.QuadPart;

    vpData->GuestVmcb.StateSaveArea.GdtrBase = currentGdtr.Base;
    vpData->GuestVmcb.StateSaveArea.GdtrLimit = currentGdtr.Limit;
    vpData->GuestVmcb.StateSaveArea.IdtrBase = currentIdtr.Base;
    vpData->GuestVmcb.StateSaveArea.IdtrLimit = currentIdtr.Limit;

    vpData->GuestVmcb.StateSaveArea.CsLimit = GetSegmentLimit(Context->SegCs);
    vpData->GuestVmcb.StateSaveArea.DsLimit = GetSegmentLimit(Context->SegDs);
    vpData->GuestVmcb.StateSaveArea.EsLimit = GetSegmentLimit(Context->SegEs);
    vpData->GuestVmcb.StateSaveArea.SsLimit = GetSegmentLimit(Context->SegSs);
    vpData->GuestVmcb.StateSaveArea.CsSelector = Context->SegCs;
    vpData->GuestVmcb.StateSaveArea.DsSelector = Context->SegDs;
    vpData->GuestVmcb.StateSaveArea.EsSelector = Context->SegEs;
    vpData->GuestVmcb.StateSaveArea.SsSelector = Context->SegSs;
    vpData->GuestVmcb.StateSaveArea.CsAttrib = SvGetSegmentAccessRight(Context->SegCs, currentGdtr.Base);
    vpData->GuestVmcb.StateSaveArea.DsAttrib = SvGetSegmentAccessRight(Context->SegDs, currentGdtr.Base);
    vpData->GuestVmcb.StateSaveArea.EsAttrib = SvGetSegmentAccessRight(Context->SegEs, currentGdtr.Base);
    vpData->GuestVmcb.StateSaveArea.SsAttrib = SvGetSegmentAccessRight(Context->SegSs, currentGdtr.Base);

    vpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    vpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    vpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    vpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    vpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    vpData->GuestVmcb.StateSaveArea.Rflags = Context->EFlags;
    vpData->GuestVmcb.StateSaveArea.Rsp = Context->Rsp;
    vpData->GuestVmcb.StateSaveArea.Rip = Context->Rip;
    vpData->GuestVmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

    vpData->HostStackLayout.Reserved1 = MAXUINT64;
    vpData->HostStackLayout.SharedVpData = sharedVpData;
    vpData->HostStackLayout.Self = vpData;
    vpData->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    vpData->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;

    __writemsr(IA32_MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);

    __svm_vmsave(vpData->HostStackLayout.HostVmcbPa);
    __svm_clgi();
    _enable();
}
/*!
    @brief      TBD.

    @details    TBD.

    @param[in]  TBD - TBD.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvVirtualizeProcessor (
    _In_opt_ PVOID Context
    )
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    PVIRTUAL_PROCESSOR_DATA vpData;
    CONTEXT currentContext;
    KIRQL oldIrql;

    SV_DEBUG_BREAK();

    vpData = nullptr;
    oldIrql = KeRaiseIrqlToDpcLevel();

    if (!ARGUMENT_PRESENT(Context))
    {
        status = STATUS_INVALID_PARAMETER_1;
        goto Exit;
    }

    sharedVpData = reinterpret_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(Context);

    vpData = reinterpret_cast<PVIRTUAL_PROCESSOR_DATA>(
                    SvAllocatePageAlingedPhysicalMemory(sizeof(VIRTUAL_PROCESSOR_DATA)));
    if (vpData == nullptr)
    {
        SvDebugPrint("Insufficient memory.");
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);

    RtlCaptureContext(&currentContext);

    // Is Guest mode?
    if (SvIsSimpleSvmInstalled() == FALSE)
    {
        SvDebugPrint("Attempting to virtualize the processor.");
        SvPrepareForVirtualization(vpData, sharedVpData, &currentContext);
        SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        //
        // Should never reach here.
        //
        SV_DEBUG_BREAK();
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

    SvDebugPrint("The processor has been virtualized.");
    status = STATUS_SUCCESS;

Exit:
    KeLowerIrql(oldIrql);

    if ((!NT_SUCCESS(status)) &&
        (vpData != nullptr))
    {
        SvFreePageAlingedPhysicalMemory(vpData);
    }
    return status;
}

/*!
    @brief      Execute a callback on all processors one-by-one.

    @details    This function execute Callback with Context as a parameter for
                each processor on the current IRQL. If the callback returned
                non-STATUS_SUCCESS value or any error occurred, this function
                stops execution of the callback and returns the error code.

                When NumOfProcessorCompleted is not NULL, this function always
                set a number of processors that successfully executed the
                callback.

    @param[in]  Callback - A function to execute on all processors.
    @param[in]  Context - A parameter to pass to the callback.
    @param[out] NumOfProcessorCompleted - A pointer to receive a number of
                processors executed the callback successfully.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvExecuteOnEachProcessor (
    _In_ NTSTATUS (*Callback)(PVOID),
    _In_opt_ PVOID Context,
    _Out_opt_ PULONG NumOfProcessorCompleted
    )
{
    NTSTATUS status;
    ULONG numOfProcessors;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;
    ULONG i;

    status = STATUS_SUCCESS;

    //
    // Get a number of processors on this system.
    //
    numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (i = 0; i < numOfProcessors; i++)
    {
        //
        // Convert from an index to a processor number.
        //
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        //
        // Switch execution of this code to a processor #i.
        //
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        //
        // Execute the callback.
        //
        status = Callback(Context);

        //
        // Revert the previously executed processor.
        //
        KeRevertToUserGroupAffinityThread(&oldAffinity);

        //
        // Exit if the callback returned error.
        //
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

Exit:
    //
    // i must be the same as the number of processors on the system when this
    // function returns STATUS_SUCCESS;
    //
    NT_ASSERT(!NT_SUCCESS(status) || i == numOfProcessors);

    //
    // Set a number of processors that successfully executed callback if the
    // out parameter is present.
    //
    if (ARGUMENT_PRESENT(NumOfProcessorCompleted))
    {
        *NumOfProcessorCompleted = i;
    }
    return status;
}

/*!
    @brief      De-virtualize the current processor if virtualized.

    @details    This function asks SimpleSVM hypervisor to deactivate itself
                through CPUID with a back-door function id and frees per
                processor data if it is returned. If the SimpleSvm is not
                installed, this function does nothing.

    @param[in]  Context - An out pointer to receive an address of shared data.

    @result     Always STATUS_SUCCESS.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvDevirtualizeProcessor (
    _In_opt_ PVOID Context
    )
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    UINT64 high, low;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PSHARED_VIRTUAL_PROCESSOR_DATA *sharedVpDataPtr;

    if (!ARGUMENT_PRESENT(Context))
    {
        goto Exit;
    }

    //
    // Ask SimpleSVM hypervisor to deactivate itself. If the hypervisor is
    // installed, this EAX is set to 'SSVM', and ECX:EDX indicates an address
    // of per processor data to be freed.
    //
    __cpuidex(registers, SV_CPUID_UNLOAD_SIMPLESVM, SV_CPUID_UNLOAD_SIMPLESVM);
    if (registers[0] != 'SSVM')
    {
        goto Exit;
    }

    SvDebugPrint("The processor has been de-virtualized");

    //
    // Get an address of per processor data indicated by ECX:EDX.
    //
    high = registers[2];
    low = registers[3] & MAXUINT32;
    vpData = reinterpret_cast<PVIRTUAL_PROCESSOR_DATA>(high << 32 | low);
    NT_ASSERT(vpData->HostStackLayout.Reserved1 == MAXUINT64);

    //
    // Save an address of shared data, then free per processor data.
    //
    sharedVpDataPtr = reinterpret_cast<PSHARED_VIRTUAL_PROCESSOR_DATA *>(Context);
    *sharedVpDataPtr = vpData->HostStackLayout.SharedVpData;
    SvFreePageAlingedPhysicalMemory(vpData);

Exit:
    return STATUS_SUCCESS;
}

/*!
    @brief      De-virtualize all virtualized processors.

    @details    This function execute a callback to de-virtualize a processor on
                all processors, and frees shared data when the callback returned
                its pointer from a hypervisor.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
VOID
SvDevirtualizeAllProcessors (
    VOID
    )
{
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;

    sharedVpData = nullptr;

    SvExecuteOnEachProcessor(SvDevirtualizeProcessor, &sharedVpData, nullptr);
    if (sharedVpData != nullptr)
    {
        SvFreePageAlingedPhysicalMemory(sharedVpData);
    }
}

/*!
    @brief      Build pass-through style page tables used in nested paging.

    @details    This function build page tables used in Nested Page Tables. The
                page tables are used to translate from a guest physical address
                to a system physical address and pointed by the NCr3 field of
                VMCB, like the traditional page tables are pointed by CR3.

                The nested page tables built in this function are set to
                translate a guest physical address to the same system physical
                address. For example, guest physical address 0x1000 is
                translated into system physical address 0x1000.

                In order to save memory to build nested page tables, 2MB large
                pages are used (as opposed to the standard pages that describe
                translation only for 4K granularity. Also, only up to 512 GB of
                translation is built. 1GB huge pages are not used due to VMware
                not supporting this feature.

    @param[out] SharedVpData - Out buffer to build nested page tables.
 */
_IRQL_requires_same_
static
VOID
SvBuildNestedPageTables (
    _Out_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData
    )
{
    ULONG64 pdpBasePa, pdeBasePa, translationPa;

    //
    // Build only one PML4 entry. This entry has subtables that control up to
    // 512GB physical memory. PFN points to a base physical address of the page
    // directory pointer table.
    //
    pdpBasePa = MmGetPhysicalAddress(&SharedVpData->PdpEntries).QuadPart;
    SharedVpData->Pml4Entries[0].Fields.PageFrameNumber = pdpBasePa >> PAGE_SHIFT;

    //
    // The US (User) bit of all nested page table entries to be translated
    // without #VMEXIT, as all guest accesses are treated as user accesses at
    // the nested level. Also, the RW (Write) bit of nested page table entries
    // that corresponds to guest page tables must be 1 since all guest page table
    // accesses are threated as write access. See "Nested versus Guest Page
    // Faults, Fault Ordering" for more details.
    //
    // Nested page tables built here set 1 to those bits for all entries, so
    // that all translation can complete without triggering #VMEXIT. This does
    // not lower security since security checks are done twice independently:
    // based on guest page tables, and nested page tables. See "Nested versus
    // Guest Page Faults, Fault Ordering" for more details.
    //
    SharedVpData->Pml4Entries[0].Fields.Valid = 1;
    SharedVpData->Pml4Entries[0].Fields.Write = 1;
    SharedVpData->Pml4Entries[0].Fields.User = 1;

    //
    // One PML4 entry controls 512 page directory pointer entires.
    //
    for (ULONG64 i = 0; i < 512; i++)
    {
        //
        // PFN points to a base physical address of the page directory table.
        //
        pdeBasePa = MmGetPhysicalAddress(&SharedVpData->PdeEntries[i][0]).QuadPart;
        SharedVpData->PdpEntries[i].Fields.PageFrameNumber = pdeBasePa >> PAGE_SHIFT;
        SharedVpData->PdpEntries[i].Fields.Valid = 1;
        SharedVpData->PdpEntries[i].Fields.Write = 1;
        SharedVpData->PdpEntries[i].Fields.User = 1;

        //
        // One page directory entry controls 512 page directory entries.
        //
        for (ULONG64 j = 0; j < 512; j++)
        {
            //
            // PFN points to a base physical address of system physical address
            // to be translated from a guest physical address. Set the PS
            // (LargePage) bit to indicate that this is a large page and no
            // subtable exists.
            //
            translationPa = (i * 512) + j;
            SharedVpData->PdeEntries[i][j].Fields.PageFrameNumber = translationPa;
            SharedVpData->PdeEntries[i][j].Fields.Valid = 1;
            SharedVpData->PdeEntries[i][j].Fields.Write = 1;
            SharedVpData->PdeEntries[i][j].Fields.User = 1;
            SharedVpData->PdeEntries[i][j].Fields.LargePage = 1;
        }
    }
}

/*!
    @brief      Test whether the current processor support the SVM feature.

    @details    This function tests whether the current processor has enough
                features to run SimpleSvm, especially about SVM features. Also,
                See: Enabling SVM
                See: Enabling Nested Paging

    @result     TRUE if the processor supports the SVM feature; otherwise, FALSE.
 */
_IRQL_requires_same_
_Check_return_
static
BOOLEAN
SvIsSvmSupported (
    VOID
    )
{
    BOOLEAN svmSupported;
    int registers[4];   // EAX, EBX, ECX, and EDX
    ULONG64 vmcr;

    svmSupported = FALSE;

    //
    // Test if the current processor is AMD one. An AMD processor should return
    // "AuthenticAMD" from CPUID function 0.
    //
    __cpuid(registers, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
    if ((registers[1] != 'htuA') ||
        (registers[3] != 'itne') ||
        (registers[2] != 'DMAc'))
    {
        goto Exit;
    }

    //
    // Test if the SVM feature is supported by the current processor.
    //
    __cpuid(registers, 0x80000001);
    if ((registers[2] & CPUID_FN8000_0001_ECX_SVM) == 0)
    {
        goto Exit;
    }

    //
    // Test if the Nested Page Tables feature is supported by the current
    // processor.
    //
    __cpuid(registers, 0x8000000a);
    if ((registers[3] & CPUID_FN8000_000A_EDX_NP) == 0)
    {
        goto Exit;
    }

    //
    // Test if the SVM feature can be enabled. When VM_CR.SVMDIS is set,
    // EFER.SVME cannot be 1; therefore, SVM cannot be enabled. When
    // VM_CR.SVMDIS is clear, EFER.SVME can be written normally and SVM can be
    // enabled.
    //
    vmcr = __readmsr(IA32_MSR_VM_CR);
    if ((vmcr & VM_CR_SVMDIS) != 0)
    {
        goto Exit;
    }

    svmSupported = TRUE;

Exit:
    return svmSupported;
}

/*!
    @brief      Virtualizes all processors on the system.

    @details    This function attempts to virtualize all processors on the
                system, and returns STATUS_SUCCESS if all processors are
                successfully virtualized. If any processor is not virtualized,
                this function de-virtualizes all processors and returns an error
                code.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvVirtualizeAllProcessors (
    VOID
    )
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    ULONG numOfProcessorsCompleted;

    sharedVpData = nullptr;
    numOfProcessorsCompleted = 0;

    //
    // Test whether the current processor supports all required SVM features. If
    // not, exit as error.
    //
    if (SvIsSvmSupported() == FALSE)
    {
        SvDebugPrint("SVM is not fully supported on this processor.");
        status = STATUS_HV_FEATURE_UNAVAILABLE;
        goto Exit;
    }

    //
    // Allocate a data structure shared across all processors. This data is
    // page tables used for Nested Page Tables.
    //

    // TODO: need not be contigunouse memory
    sharedVpData = reinterpret_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(
            SvAllocatePageAlingedPhysicalMemory(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA)));
    if (sharedVpData == nullptr)
    {
        SvDebugPrint("Insufficient memory.");
        status = STATUS_NO_MEMORY;
        goto Exit;
    }

    //
    // Build page tables for Nested Page Table.
    //
    SvBuildNestedPageTables(sharedVpData);

    //
    // Execute SvVirtualizeProcessor on and virtualize each processor one-by-one.
    // How many processors were successfully virtualized is stored in the third
    // parameter.
    //
    // STATUS_SUCCESS is returned if all processor are successfully virtualized.
    // When any error occurs while virtualizing processors, this function does
    // not attempt to virtualize the rest of processor. Therefore, only part of
    // processors on the system may have been virtualized on error. In this case,
    // it is a caller's responsibility to clean-up (de-virtualize) such
    // processors.
    //
    status = SvExecuteOnEachProcessor(SvVirtualizeProcessor,
                                      sharedVpData,
                                      &numOfProcessorsCompleted);

Exit:
    if ((!NT_SUCCESS(status)) &&
        (sharedVpData != nullptr))
    {
        //
        // On failure, after successful allocation of shared data.
        //
        if (numOfProcessorsCompleted != 0)
        {
            //
            // If one or more processors have already been virtualized,
            // de-virtualize any of those processors, and free shared data.
            //
            SvDevirtualizeAllProcessors();
        }
        else
        {
            //
            // If none of processors has not been virtualized, simply free
            // shared data.
            //
            SvFreePageAlingedPhysicalMemory(sharedVpData);
        }
    }
    return status;
}

/*!
    @brief      An entry point of this driver.

    @param[in]  DriverObject - A driver object.
    @param[in]  RegistryPath - Unused.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_Use_decl_annotations_
EXTERN_C
NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);

    SV_DEBUG_BREAK();

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    DriverObject->DriverUnload = DriverUnload;
    return SvVirtualizeAllProcessors();
}

/*!
    @brief      Driver unload callback.

    @details    This function de-virtualize all processors on the system.

    @param[in]  DriverObject - Unused.
 */
_Use_decl_annotations_
static
VOID
DriverUnload (
    PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    SV_DEBUG_BREAK();

    SvDevirtualizeAllProcessors();
}
