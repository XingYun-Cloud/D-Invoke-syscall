using System;
using System.Runtime.InteropServices;


class Delegates
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate Native.NTSTATUS NtCreateThreadEx(
        out IntPtr hThread,
        Native.ACCESS_MASK DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        bool CreateSuspended,
        uint StackZeroBits,
        uint SizeOfStackCommit,
        uint SizeOfStackReserve,
        IntPtr lpBytesBuffer
        );

    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate Native.NTSTATUS NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        Native.AllocationType AllocationType,
        uint Protect
        );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate Native.NTSTATUS NtWaitForSingleObject(
        IntPtr Object,
        bool Alertable,
        uint Timeout
        );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void RtlInitUnicodeString(ref Native.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtQueryInformationProcess(
                IntPtr processHandle,
                Native.PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref UInt32 returnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void RtlZeroMemory(
                IntPtr Destination,
                int length);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtWriteVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                IntPtr Buffer,
                UInt32 BufferLength,
                ref UInt32 BytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtProtectVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                ref IntPtr RegionSize,
                UInt32 NewProtect,
                ref UInt32 OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtFreeVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                ref IntPtr RegionSize,
                Native.AllocationType FreeType);
}