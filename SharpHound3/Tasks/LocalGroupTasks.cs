using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class LocalGroupTasks
    {
        internal static LdapWrapper GetLocalGroupMembers(LdapWrapper wrapper)
        {
            if (wrapper is Computer computer && !computer.PingFailed)
            {
                var opts = Options.Instance.ResolvedCollectionMethods;
                if ((opts & CollectionMethodResolved.DCOM) != 0)
                    computer.DcomUsers = GetNetLocalGroupMembers(computer, LocalGroupRids.DcomUsers).ToArray();

                if ((opts & CollectionMethodResolved.LocalAdmin) != 0)
                    computer.LocalAdmins = GetNetLocalGroupMembers(computer, LocalGroupRids.Administrators).ToArray();

                if ((opts & CollectionMethodResolved.RDP) != 0)
                    computer.RemoteDesktopUsers = GetNetLocalGroupMembers(computer, LocalGroupRids.RemoteDesktopUsers).ToArray();

                if ((opts & CollectionMethodResolved.PSRemote) != 0)
                    computer.PSRemoteUsers = GetNetLocalGroupMembers(computer, LocalGroupRids.PsRemote).ToArray();
            }

            return wrapper;
        }

        private static readonly Lazy<byte[]> LocalSidBytes = new Lazy<byte[]>(() =>
        {
            var sid = new SecurityIdentifier("S-1-5-32");
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            return bytes;
        });

        private static IEnumerable<GroupMember> GetNetLocalGroupMembers(Computer computer, LocalGroupRids rid)
        {
            var sids = new IntPtr[0];
            var machineSid = "DUMMYSTRINGNEVERMATCH";

            var task = Task.Run(() => CallLocalGroupApi(computer, rid, out sids, out machineSid));

            var success = task.Wait(TimeSpan.FromSeconds(10));

            if (!success)
            {
                OutputTasks.AddComputerError(new ComputerError
                {
                    ComputerName = computer.DisplayName,
                    Error = "Timeout",
                    Task = $"GetNetLocalGroup-{rid}"
                });
                yield break;
            }

            var taskResult = task.Result;
            if (!taskResult)
                yield break;

            if (Options.Instance.DumpComputerErrors)
                OutputTasks.AddComputerError(new ComputerError
                {
                    ComputerName = computer.DisplayName,
                    Error = "Success",
                    Task = $"GetNetLocaGroup-{rid}"
                });

            foreach (var baseSid in sids)
            {
                string sid;
                LdapTypeEnum type;
                try
                {
                    sid = new SecurityIdentifier(baseSid).Value;
                    if (sid.StartsWith(machineSid))
                        continue;
                    
                    if (CommonPrincipal.GetCommonSid(sid, out var common))
                    {
                        sid = Helpers.ConvertCommonSid(sid, null);
                        type = common.Type;
                    }
                    else
                    {
                        type = Helpers.LookupSidType(sid);
                    }
                }
                catch
                {
                    continue;
                }

                yield return new GroupMember
                {
                    MemberType = type,
                    MemberName = sid
                };
            }
        }

        private static bool CallLocalGroupApi(Computer computer, LocalGroupRids rid, out IntPtr[] sids, out string machineSid)
        {
            var serverHandle = IntPtr.Zero;
            var domainHandle = IntPtr.Zero;
            var aliasHandle = IntPtr.Zero;
            var machineSidPtr = IntPtr.Zero;
            var members = IntPtr.Zero;

            var server = new UNICODE_STRING(computer.APIName);
            var objectAttributes = new OBJECT_ATTRIBUTES();
            NtStatus status;
            sids = new IntPtr[0];
            machineSid = null;

            try
            {
                //0x1 = SamServerLookupDomain, 0x20 = SamServerConnect
                status = SamConnect(ref server, out serverHandle, 0x1 | 0x20, ref objectAttributes);

                switch (status)
                {
                    case NtStatus.StatusRpcServerUnavailable:
                        if (Options.Instance.DumpComputerErrors)
                            OutputTasks.AddComputerError(new ComputerError
                            {
                                ComputerName = computer.DisplayName,
                                Error = status.ToString(),
                                Task = $"GetNetLocalGroup-{rid}"
                            });
                        
                        return false;
                    case NtStatus.StatusSuccess:
                        break;
                    default:
                        if (Options.Instance.DumpComputerErrors)
                            OutputTasks.AddComputerError(new ComputerError
                            {
                                ComputerName = computer.DisplayName,
                                Error = status.ToString(),
                                Task = $"GetNetLocalGroup-{rid}"
                            });
                        return false;
                }

                try
                {
                    var samAccountName = new UNICODE_STRING(computer.SamAccountName);
                    SamLookupDomainInSamServer(serverHandle, ref samAccountName, out machineSidPtr);
                    machineSid = new SecurityIdentifier(machineSidPtr).Value;
                }
                catch
                {
                    machineSid = "DUMMYSTRINGNEVERMATCH";
                }

                //0x200 = Lookup
                status = SamOpenDomain(serverHandle, 0x200, LocalSidBytes.Value, out domainHandle);

                if (status != NtStatus.StatusSuccess)
                {
                    if (Options.Instance.DumpComputerErrors)
                        OutputTasks.AddComputerError(new ComputerError
                        {
                            ComputerName = computer.DisplayName,
                            Error = status.ToString(),
                            Task = $"GetNetLocalGroup-{rid}"
                        });
                    return false;
                }


                //0x4 = ListMembers
                status = SamOpenAlias(domainHandle, 0x4, (int)rid, out aliasHandle);

                if (status != NtStatus.StatusSuccess)
                {
                    if (Options.Instance.DumpComputerErrors)
                        OutputTasks.AddComputerError(new ComputerError
                        {
                            ComputerName = computer.DisplayName,
                            Error = status.ToString(),
                            Task = $"GetNetLocalGroup-{rid}"
                        });

                }


                status = SamGetMembersInAlias(aliasHandle, out members, out var count);

                if (status != NtStatus.StatusSuccess)
                {
                    if (Options.Instance.DumpComputerErrors)
                        OutputTasks.AddComputerError(new ComputerError
                        {
                            ComputerName = computer.DisplayName,
                            Error = status.ToString(),
                            Task = $"GetNetLocalGroup-{rid}"
                        });
                    return false;
                }

                if (count == 0)
                {
                    return false;
                }

                //Copy the IntPtr to an array so we can loop over it
                sids = new IntPtr[count];
                Marshal.Copy(members, sids, 0, count);

                return true;
            }
            finally
            {
                if (serverHandle != IntPtr.Zero)
                    SamCloseHandle(serverHandle);
                if (domainHandle != IntPtr.Zero)
                    SamCloseHandle(domainHandle);
                if (aliasHandle != IntPtr.Zero)
                    SamCloseHandle(aliasHandle);

                if (machineSidPtr != IntPtr.Zero)
                    SamFreeMemory(machineSidPtr);
                if (members != IntPtr.Zero)
                    SamFreeMemory(members);
            }
        }

        private enum LocalGroupRids
        {
            Administrators = 544,
            RemoteDesktopUsers = 555,
            DcomUsers = 562,
            PsRemote = 580
        }

        #region SamRPC Imports

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamConnect(ref UNICODE_STRING serverName, out IntPtr serverHandle, int desiredAccess,
            ref OBJECT_ATTRIBUTES objectAttributes);

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamOpenDomain(IntPtr serverHandle, int desiredAccess, IntPtr domainId,
            out IntPtr domainHandle);

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamLookupDomainInSamServer(IntPtr serverHandle, ref UNICODE_STRING name,
            out IntPtr securityIdentifier);

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamOpenDomain(IntPtr serverHandle, int desiredAccess,
            [MarshalAs(UnmanagedType.LPArray)] byte[] securityIdentifierBytes, out IntPtr domainHandle);

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamOpenAlias(IntPtr domainHandle, int desiredAccess, int aliasId,
            out IntPtr aliasHandle);

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamGetMembersInAlias(IntPtr aliasHandle, out IntPtr members, out int count);

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamCloseHandle(IntPtr handle);

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamFreeMemory(IntPtr pointer);
        #endregion

        #region PInvoke Structs/Enums

        internal enum NtStatus
        {
            StatusSuccess = 0x0,
            StatusMoreEntries = 0x105,
            StatusSomeMapped = 0x107,
            StatusInvalidHandle = unchecked((int)0xC0000008),
            StatusInvalidParameter = unchecked((int)0xC000000D),
            StatusAccessDenied = unchecked((int)0xC0000022),
            StatusObjectTypeMismatch = unchecked((int)0xC0000024),
            StatusNoSuchDomain = unchecked((int)0xC00000DF),
            StatusRpcServerUnavailable = unchecked((int)0xC0020017)
        }

        internal struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)] private string buffer;

            internal UNICODE_STRING(string s)
            {
                if (string.IsNullOrEmpty(s))
                    buffer = string.Empty;
                else
                    buffer = s;

                Length = (ushort)(2 * buffer.Length);
                MaximumLength = Length;
            }

            public override string ToString()
            {
                if (Length != 0)
                    return buffer.Substring(0, (int)(Length / 2));

                return string.Empty;
            }
        }

        internal struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr QualityOfService;
            private IntPtr _objectName;
            public UNICODE_STRING ObjectName;

            public void Dispose()
            {
                if (_objectName == IntPtr.Zero)
                    return;

                Marshal.DestroyStructure(_objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(_objectName);
                _objectName = IntPtr.Zero;
            }
        }
        #endregion
    }
}