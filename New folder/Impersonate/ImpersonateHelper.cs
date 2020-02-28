﻿using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace StudyConsole
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ProfileInfo
    {
        /// 
        /// Specifies the size of the structure, in bytes.
        /// 
        public int dwSize;

        /// 
        /// This member can be one of the following flags: PI_NOUI or PI_APPLYPOLICY
        /// 
        public int dwFlags;

        /// 
        /// Pointer to the name of the user. 
        /// This member is used as the base name of the directory in which to store a new profile. 
        /// 
        public string lpUserName;

        /// 
        /// Pointer to the roaming user profile path. 
        /// If the user does not have a roaming profile, this member can be NULL.
        /// 
        public string lpProfilePath;

        /// 
        /// Pointer to the default user profile path. This member can be NULL. 
        /// 
        public string lpDefaultPath;

        /// 
        /// Pointer to the name of the validating domain controller, in NetBIOS format. 
        /// If this member is NULL, the Windows NT 4.0-style policy will not be applied. 
        /// 
        public string lpServerName;

        /// 
        /// Pointer to the path of the Windows NT 4.0-style policy file. This member can be NULL. 
        /// 
        public string lpPolicyPath;

        /// 
        /// Handle to the HKEY_CURRENT_USER registry key. 
        /// 
        public IntPtr hProfile;
    }

    /// <summary>
    /// Provides the functionality of impersonating a domain or local PC user.
    /// Microsoft KB link for impersonation: http://support.microsoft.com/kb/306158
    /// </summary>
    public class ImpersonateHelper
    {
        public const int LOGON32_LOGON_INTERACTIVE = 2;
        public const int LOGON32_PROVIDER_DEFAULT = 0;

        #region PInvoke
        [DllImport("advapi32.dll")]
        public static extern int LogonUser(String lpszUserName,
            String lpszDomain,
            String lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DuplicateToken(IntPtr hToken, int impersonationLevel, ref IntPtr hNewToken);

        /// <summary>
        /// A process should call the RevertToSelf function after finishing any impersonation begun by using the DdeImpersonateClient, ImpersonateDdeClientWindow, ImpersonateLoggedOnUser, ImpersonateNamedPipeClient, ImpersonateSelf, ImpersonateAnonymousToken or SetThreadToken function.
        /// If RevertToSelf fails, your application continues to run in the context of the client, which is not appropriate. You should shut down the process if RevertToSelf fails.
        /// RevertToSelf Function: http://msdn.microsoft.com/en-us/library/aa379317(VS.85).aspx
        /// </summary>
        /// <returns>A boolean value indicates the function succeeded or not.</returns>
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LoadUserProfile(IntPtr hToken, ref ProfileInfo lpProfileInfo);

        [DllImport("Userenv.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool UnloadUserProfile(IntPtr hToken, IntPtr lpProfileInfo);

        #endregion

        private static WindowsImpersonationContext m_ImpersonationContext = null;

        public static void DoImpersonation()
        {
            WindowsIdentity m_ImpersonatedUser;
            IntPtr token = IntPtr.Zero;
            IntPtr tokenDuplicate = IntPtr.Zero;
            const int SecurityImpersonation = 2;
            const int TokenType = 1;

            try
            {
                if (RevertToSelf())
                {
                    Console.WriteLine("Before impersonation: " +
                                      WindowsIdentity.GetCurrent().Name);

                    String userName = "TempUser";
                    IntPtr password = GetPassword();

                    if (LogonUser(userName, Environment.MachineName, "!@#$QWERasdf", LOGON32_LOGON_INTERACTIVE,
                                  LOGON32_PROVIDER_DEFAULT, ref token) != 0)
                    {
                        if (DuplicateToken(token, SecurityImpersonation, ref tokenDuplicate) != 0)
                        {
                            m_ImpersonatedUser = new WindowsIdentity(tokenDuplicate);
                            using (m_ImpersonationContext = m_ImpersonatedUser.Impersonate())
                            {
                                if (m_ImpersonationContext != null)
                                {
                                    Console.WriteLine("After Impersonation succeeded: " + Environment.NewLine +
                                                      "User Name: " +
                                                      WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).Name +
                                                      Environment.NewLine +
                                                      "SID: " +
                                                      WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).User.
                                                          Value);

                                    #region LoadUserProfile
                                    // Load user profile
                                    ProfileInfo profileInfo = new ProfileInfo();
                                    profileInfo.dwSize = Marshal.SizeOf(profileInfo);
                                    profileInfo.lpUserName = userName;
                                    profileInfo.dwFlags = 1;
                                    Boolean loadSuccess = LoadUserProfile(tokenDuplicate, ref profileInfo);

                                    if (!loadSuccess)
                                    {
                                        Console.WriteLine("LoadUserProfile() failed with error code: " +
                                                          Marshal.GetLastWin32Error());
                                        throw new Win32Exception(Marshal.GetLastWin32Error());
                                    }

                                    if (profileInfo.hProfile == IntPtr.Zero)
                                    {
                                        Console.WriteLine(
                                            "LoadUserProfile() failed - HKCU handle was not loaded. Error code: " +
                                            Marshal.GetLastWin32Error());
                                        throw new Win32Exception(Marshal.GetLastWin32Error());
                                    }
                                    #endregion

                                    CloseHandle(token);
                                    CloseHandle(tokenDuplicate);

                                    // Do tasks after impersonating successfully
                                    AccessFileSystem();

                                    // Access HKCU after loading user's profile
                                    AccessHkcuRegistry(profileInfo.hProfile);

                                    // Unload user profile
                                    // MSDN remarks http://msdn.microsoft.com/en-us/library/bb762282(VS.85).aspx 
                                    // Before calling UnloadUserProfile you should ensure that all handles to keys that you have opened in the 
                                    // user's registry hive are closed. If you do not close all open registry handles, the user's profile fails 
                                    // to unload. For more information, see Registry Key Security and Access Rights and Registry Hives.
                                    UnloadUserProfile(tokenDuplicate, profileInfo.hProfile);

                                    // Undo impersonation
                                    m_ImpersonationContext.Undo();
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("DuplicateToken() failed with error code: " + Marshal.GetLastWin32Error());
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }
                }
            }
            catch (Win32Exception we)
            {
                throw we;
            }
            catch
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
                if (tokenDuplicate != IntPtr.Zero) CloseHandle(tokenDuplicate);

                Console.WriteLine("After finished impersonation: " + WindowsIdentity.GetCurrent().Name);
            }
        }

        private static void AccessHkcuRegistry(IntPtr hkcuHandle)
        {
            // Access registry HKCU
            using (SafeRegistryHandle safeHandle = new SafeRegistryHandle(hkcuHandle, true))
            {
                using (RegistryKey tempUserHKCU = RegistryKey.FromHandle(safeHandle))
                {
                    // Unum all sub keys under tempuser's HKCU 
                    String[] keys = tempUserHKCU.GetSubKeyNames();

                    // Create a new sub key under tempuser's HKCU 
                    using (RegistryKey tempKeyByWayne = tempUserHKCU.CreateSubKey("TempKeyByWayne"))
                    {
                        Console.WriteLine("TempKeyByWayne under TempUser's HKCU was created!");
                        // Ensure priviledge
                        //RegistrySecurity registrySecurity = new RegistrySecurity();
                        //RegistryAccessRule accessRule = new RegistryAccessRule(Environment.MachineName + "\\" + userName,
                        //                                                       RegistryRights.TakeOwnership,
                        //                                                       InheritanceFlags.ContainerInherit,
                        //                                                       PropagationFlags.None,
                        //                                                       AccessControlType.Allow);
                        //registrySecurity.SetAccessRule(accessRule);
                        //tempKeyByWayne.SetAccessControl(registrySecurity);

                        // Create a new String value under created TempKeyByWayne subkey
                        tempKeyByWayne.SetValue("StrType", "TempContent", RegistryValueKind.String);

                        // Read the value
                        using (RegistryKey regKey = tempUserHKCU.OpenSubKey("TempKeyByWayne"))
                        {
                            String valueContent = regKey.GetValue("StrType") as String;
                            Console.WriteLine("HKEY_CURRENT_USER\\TempKeyByWayne\\strTyle value: " + valueContent);
                        }

                        // Delete created TempKeyByWayne subkey
                        tempUserHKCU.DeleteSubKey("TempKeyByWayne");
                        Console.WriteLine("TempKeyByWayne under TempUser's HKCU was deleted!");
                        tempKeyByWayne.Close();
                    }
                }
            }
        }

        private static void AccessFileSystem()
        {
            // Access file system %appdata% will be "C:\Users\TempUser\appdata\Roaming"
            String appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            File.AppendAllText("C:\\TempFolder\\Temp.txt", "some text...");
        }

        private static IntPtr GetPassword()
        {
            IntPtr password = IntPtr.Zero;

            using (SecureString secureString = new SecureString())
            {
                foreach (char c in "!@#$QWERasdf")
                    secureString.AppendChar(c);

                // Lock the password down
                secureString.MakeReadOnly();

                password = Marshal.SecureStringToBSTR(secureString);
            }

            return password;
        }
    }
}
