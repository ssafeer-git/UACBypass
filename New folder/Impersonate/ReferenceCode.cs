using System;
using System.Runtime.InteropServices;

namespace StudyConsole
{
    public class ReferenceCode
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct StartupInfo
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessID;
            public Int32 dwThreadID;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public extern static bool CreateProcessAsUser(IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandle,
            int dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref StartupInfo lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType,
            int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int RegLoadKey(uint hKey, string lpSubKey, string lpFile);
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int RegUnLoadKey(uint hKey, string lpSubKey);

        public static void DoImpersonation()
        {
            const int SecurityImpersonation = 2;
            const int TokenType = 1;

            //SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            //        sa.bInheritHandle = false;
            //        sa.Length = Marshal.SizeOf(sa);
            //        sa.lpSecurityDescriptor = (IntPtr)0;
            //        if (DuplicateTokenEx(token, 0x10000000, ref sa, SecurityImpersonation, TokenType, ref tokenDuplicate))

            //IntPtr lpEnvironment;
            //Boolean createEnvSuccess = CreateEnvironmentBlock(out lpEnvironment, tokenDuplicate, false);

            //if (!createEnvSuccess)
            //{
            //    Console.WriteLine("CreateEnvironmentBlock() failed with error code: " + Marshal.GetLastWin32Error());
            //    throw new Win32Exception(Marshal.GetLastWin32Error());
            //}

            //String commandLine = "C:\\Windows\\notepad.exe";
            //PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            //StartupInfo si = new StartupInfo();
            //si.cb = Marshal.SizeOf(si);
            //si.lpDesktop = "Winsta0\\Default";

            //Boolean createProcessAsUserSuccess = CreateProcessAsUser(
            //                                                 tokenDuplicate,
            //                                                 null,
            //                                                 commandLine,
            //                                                 ref sa,
            //                                                 ref sa,
            //                                                 false, 0, IntPtr.Zero,
            //                                                 "c:\\", ref si, out pi
            //                                                );

            //if (!createProcessAsUserSuccess)
            //{
            //    int error = Marshal.GetLastWin32Error();

            //    throw new System.ComponentModel.Win32Exception(error);
            //}
        }
    }
}