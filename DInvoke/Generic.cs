using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using MessyTools;

class Generic
{
    public static IntPtr GetSyscallStub(string FunctionName)
    {
        // Verify process & architecture
        bool isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
        if (IntPtr.Size == 4 && isWOW64)
        {
            throw new InvalidOperationException("Generating Syscall stubs is not supported for WOW64.");
        }

        // Find the path for ntdll by looking at the currently loaded module
        string NtdllPath = string.Empty;
        ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
            {
                NtdllPath = Mod.FileName;
            }
        }

        // Alloc module into memory for parsing
        IntPtr pModule = SharpSploit_Execution_ManualMap_Map.AllocateFileToMemory(NtdllPath);

        // Fetch PE meta data
        SharpSploit_Execution_ManualMap_PE.PE_META_DATA PEINFO = GetPeMetaData(pModule);

        // Alloc PE image memory -> RW
        IntPtr hProcess = Native.GetCurrentProcess(); // 进程句柄，当前进程为-1
        IntPtr BaseAddress = IntPtr.Zero; // 接收分配的内存地址
        IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
        UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;

        IntPtr pImage = Native.NtAllocateVirtualMemory(
            hProcess, ref BaseAddress, IntPtr.Zero, ref RegionSize,
            Native.AllocationType.Commit | Native.AllocationType.Reserve,
            (uint)Native.AllocationProtect.PAGE_READWRITE
        );

        // Write PE header to memory
        UInt32 BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

        // Write sections to memory
        foreach (SharpSploit_Execution_ManualMap_PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
        {
            // Calculate offsets
            IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
            IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

            // Write data
            BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
            if (BytesWritten != ish.SizeOfRawData)
            {
                throw new InvalidOperationException("Failed to write to memory.");
            }
        }

        // Get Ptr to function
        IntPtr pFunc = GetExportAddress(pImage, FunctionName);
        if (pFunc == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to resolve ntdll export.");
        }

        // Alloc memory for call stub
        BaseAddress = IntPtr.Zero;
        RegionSize = (IntPtr)0x50;
        IntPtr pCallStub = Native.NtAllocateVirtualMemory(
            (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
            Native.AllocationType.Commit | Native.AllocationType.Reserve,
            (uint)Native.AllocationProtect.PAGE_READWRITE
        );

        // Write call stub
        BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
        if (BytesWritten != 0x50)
        {
            throw new InvalidOperationException("Failed to write to memory.");
        }

        // Change call stub permissions
        Native.NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref RegionSize, (uint)Native.AllocationProtect.PAGE_EXECUTE_READ);

        // Free temporary allocations
        Marshal.FreeHGlobal(pModule);
        //RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;

        //Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref RegionSize, Native.AllocationType.Reserve

        //原代码有问题，参考下面两个Microsoft docs重改写
        //https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfreevirtualmemory
        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
        RegionSize = IntPtr.Zero;
        Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref RegionSize, Native.FreeType.MEM_RELEASE);

        return pCallStub;
    }

    public static SharpSploit_Execution_ManualMap_PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
    {
        SharpSploit_Execution_ManualMap_PE.PE_META_DATA PeMetaData = new SharpSploit_Execution_ManualMap_PE.PE_META_DATA();
        try
        {
            UInt32 e_lfanew = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + 0x3c));
            PeMetaData.Pe = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + e_lfanew));
            // Validate PE signature
            if (PeMetaData.Pe != 0x4550)
            {
                throw new InvalidOperationException("Invalid PE signature.");
            }
            PeMetaData.ImageFileHeader = (SharpSploit_Execution_ManualMap_PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((UInt64)pModule + e_lfanew + 0x4), typeof(SharpSploit_Execution_ManualMap_PE.IMAGE_FILE_HEADER));
            IntPtr OptHeader = (IntPtr)((UInt64)pModule + e_lfanew + 0x18);
            UInt16 PEArch = (UInt16)Marshal.ReadInt16(OptHeader);
            // Validate PE arch
            if (PEArch == 0x010b) // Image is x32
            {
                PeMetaData.Is32Bit = true;
                PeMetaData.OptHeader32 = (SharpSploit_Execution_ManualMap_PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(OptHeader, typeof(SharpSploit_Execution_ManualMap_PE.IMAGE_OPTIONAL_HEADER32));
            }
            else if (PEArch == 0x020b) // Image is x64
            {
                PeMetaData.Is32Bit = false;
                PeMetaData.OptHeader64 = (SharpSploit_Execution_ManualMap_PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(OptHeader, typeof(SharpSploit_Execution_ManualMap_PE.IMAGE_OPTIONAL_HEADER64));
            }
            else
            {
                throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
            }
            // Read sections
            SharpSploit_Execution_ManualMap_PE.IMAGE_SECTION_HEADER[] SectionArray = new SharpSploit_Execution_ManualMap_PE.IMAGE_SECTION_HEADER[PeMetaData.ImageFileHeader.NumberOfSections];
            for (int i = 0; i < PeMetaData.ImageFileHeader.NumberOfSections; i++)
            {
                IntPtr SectionPtr = (IntPtr)((UInt64)OptHeader + PeMetaData.ImageFileHeader.SizeOfOptionalHeader + (UInt32)(i * 0x28));
                SectionArray[i] = (SharpSploit_Execution_ManualMap_PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(SectionPtr, typeof(SharpSploit_Execution_ManualMap_PE.IMAGE_SECTION_HEADER));
            }
            PeMetaData.Sections = SectionArray;
        }
        catch
        {
            throw new InvalidOperationException("Invalid module base specified.");
        }
        return PeMetaData;
    }

    public static Native.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Native.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
    {
        // Craft an array for the arguments
        object[] funcargs =
        {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

        Native.NTSTATUS retValue = (Native.NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(Delegates.RtlInitUnicodeString), ref funcargs);

        // Update the modified variables
        ModuleHandle = (IntPtr)funcargs[3];

        return retValue;
    }

    public static void RtlInitUnicodeString(ref Native.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
    {
        // Craft an array for the arguments
        object[] funcargs =
        {
                DestinationString, SourceString
            };

        DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString), ref funcargs);

        // Update the modified variables
        DestinationString = (Native.UNICODE_STRING)funcargs[0];
    }

    /// <summary>
    /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="DLLName">Name of the DLL.</param>
    /// <param name="FunctionName">Name of the function.</param>
    /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
    /// <param name="Parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
    /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
    public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
    {
        IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
        return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
    }

    /// <summary>
    /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
    /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
    /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
    /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
    public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
    {
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
        return funcDelegate.DynamicInvoke(Parameters);
    }

    /// <summary>
    /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
    /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
    public static IntPtr LoadModuleFromDisk(string DLLPath)
    {
        Native.UNICODE_STRING uModuleName = new Native.UNICODE_STRING();
        RtlInitUnicodeString(ref uModuleName, DLLPath);

        IntPtr hModule = IntPtr.Zero;
        Native.NTSTATUS CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
        if (CallResult != Native.NTSTATUS.Success || hModule == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }

        return hModule;
    }

    /// <summary>
    /// Helper for getting the base address of a module loaded by the current process. This base
    /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
    /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
    /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
    public static IntPtr GetLoadedModuleAddress(string DLLName)
    {
        ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
            {
                return Mod.BaseAddress;
            }
        }
        return IntPtr.Zero;
    }

    /// <summary>
    /// Helper for getting the pointer to a function from a DLL loaded by the process.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
    /// <param name="FunctionName">Name of the exported procedure.</param>
    /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
    /// <returns>IntPtr for the desired function.</returns>
    public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
    {
        IntPtr hModule = GetLoadedModuleAddress(DLLName);
        if (hModule == IntPtr.Zero && CanLoadFromDisk)
        {
            hModule = LoadModuleFromDisk(DLLName);
            if (hModule == IntPtr.Zero)
            {
                throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
            }
        }
        else if (hModule == IntPtr.Zero)
        {
            throw new DllNotFoundException(DLLName + ", Dll was not found.");
        }

        return GetExportAddress(hModule, FunctionName);
    }

    /// <summary>
    /// Given a module base address, resolve the address of a function by manually walking the module export table.
    /// </summary>
    /// <author>Ruben Boonen (@FuzzySec)</author>
    /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
    /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
    /// <returns>IntPtr for the desired function.</returns>
    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
    {
        IntPtr FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr == IntPtr.Zero)
        {
            // Export not found
            throw new MissingMethodException(ExportName + ", export not found.");
        }
        return FunctionPtr;
    }
}