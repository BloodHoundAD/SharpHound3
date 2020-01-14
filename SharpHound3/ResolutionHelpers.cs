using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using DnsClient;
using SharpHound3.Enums;
using SharpHound3.JSON;

namespace SharpHound3
{
    internal class ResolutionHelpers
    {
        private static readonly ConcurrentDictionary<string, string> SidToDomainNameCache = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, string> NetbiosDomainNameCache = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, string> DomainControllerCache = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, string> HostResolutionMap = new ConcurrentDictionary<string, string>();
        private static readonly Cache AppCache = Cache.Instance;
        private static readonly string[] GroupMembershipLookupProps = { "samaccounttype", "objectsid", "objectclass" };
        private static readonly string[] OUGuidLookupProps = {"objectguid"};
        private static readonly string[] ResolutionProps = { "samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname" };

        // The following byte stream contains the necessary message
        // to request a NetBios name from a machine
        // http://web.archive.org/web/20100409111218/http://msdn.microsoft.com/en-us/library/system.net.sockets.socket.aspx
        private static readonly byte[] NameRequest =
        {
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        };

        /// <summary>
        /// Tried to resolve a host to its corresponding AD SID
        /// Possible formats for hostnames:
        /// 192.168.1.1 - IP Address
        /// TESTLAB\primary - NT4 Format
        /// primary - Raw computer name
        /// MSSQL/primary - basic SPN
        /// MSSQL/primary.testlab.local - fully qualified SPN
        /// MSSQL/primary.testlab.local:1433:instance - SPN with instance and port
        /// MSSQL/primary.testlab.local:1433 - SPN with port
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        internal static async Task<string> ResolveHostToSid(string hostname, string domain)
        {
            // Strip SPN prefixes/suffixes, transform to upper case and trim $ from the end
            var normalizedHostname = Helpers.StripSPN(hostname).ToUpper().TrimEnd('$');
            
            if (HostResolutionMap.TryGetValue(normalizedHostname, out var resolvedHost))
                return resolvedHost;

            var normalizedDomain = Helpers.NormalizeDomainName(domain);

            string tempName = null;
            string tempDomain = null;

            // First lets cover cases where its not an IP address
            if (!IPAddress.TryParse(normalizedHostname, out _))
            {
                //Case 1: FQDN - primary.testlab.local. Hostname contains a .
                if (normalizedHostname.Contains("."))
                {
                    var splitName = normalizedHostname.Split('.');
                    tempName = splitName[0];
                    tempDomain = string.Join(".", splitName.Skip(1));
                }
                //Case 2: Just the NETBIOS name of the computer. We'll assume the domain is the same as the one that came in
                else
                {
                    tempName = normalizedHostname;
                    tempDomain = normalizedDomain;
                }

                //Append $ to the computer name to represent the computer account
                tempName = $"{tempName}$".ToUpper();

                var (success, sid, _) = await ResolveAccountNameToSidAndType(tempName, tempDomain);

                if (success)
                {
                    HostResolutionMap.TryAdd(normalizedHostname, sid);
                    return sid;
                }
            }

            //Next we'll try calling NetWkstaGetInfo in hopes of getting the NETBIOS name directly from the computer
            //We'll use the hostname that we started with instead of the one from our previous step
            var (wkstaSuccess, workstationInfo) = await CallNetWkstaGetInfo(normalizedHostname);
            if (wkstaSuccess)
            {
                tempName = workstationInfo.computer_name;
                tempDomain = workstationInfo.lan_group;

                //Check if the domain is empty
                if (string.IsNullOrEmpty(tempDomain))
                    tempDomain = normalizedDomain;

                if (!string.IsNullOrEmpty(tempName))
                {
                    //Append the $ to indicate this is a computer
                    tempName = $"{tempName}$".ToUpper();
                    var (success, sid, _) = await ResolveAccountNameToSidAndType(tempName, tempDomain);
                    if (success)
                    {
                        HostResolutionMap.TryAdd(normalizedHostname, sid);
                        return sid;
                    }
                }
            }

            // Next attempt is trying to request the NETBIOS name from the computer using some socket magic
            if (RequestNetbiosNameFromComputer(normalizedHostname, normalizedDomain, out tempName))
            {
                tempDomain = tempDomain ?? normalizedDomain;
                tempName = $"{tempName}$".ToUpper();
                var (success, sid, _) = await ResolveAccountNameToSidAndType(tempName, tempDomain);

                if (success)
                {
                    HostResolutionMap.TryAdd(normalizedHostname, sid);
                    return sid;
                }
            }

            //All our direct attempts to resolve have failed. We'll try some DNS resolution now
            var resolver = Helpers.GetDNSResolver(normalizedDomain);
            var resolvedHostName = (await resolver.GetHostEntryAsync(normalizedHostname))?.HostName;

            if (resolvedHostName != null)
            {
                var splitName = resolvedHostName.Split('.');
                tempName = $"{splitName[0]}$".ToUpper();
                tempDomain = string.Join(".", splitName.Skip(1));

                //Try with the domain passed in, as well as the domain from DNS
                var (success, sid, _) = await ResolveAccountNameToSidAndType(tempName, normalizedDomain);
                if (!success)
                    (success, sid, _) = await ResolveAccountNameToSidAndType(tempName, tempDomain);

                if (success)
                {
                    HostResolutionMap.TryAdd(normalizedHostname, sid);
                    return sid;
                }
            }

            //If we get here, everything has failed, and life is very sad.
            tempName = tempName ?? normalizedHostname;
            tempDomain = tempDomain ?? normalizedDomain;

            if (tempName.Contains("."))
            {
                HostResolutionMap.TryAdd(normalizedHostname, tempName);
                return tempName;
            }

            //Take our original normalized domain, and return host@domain
            tempName = $"{tempName}.{tempDomain}";
            HostResolutionMap.TryAdd(normalizedHostname, tempName);
            return tempName;
        }

        internal static string ResolveDomainNetbiosToDns(string domainName)
        {
            var key = domainName.ToUpper();
            if (NetbiosDomainNameCache.TryGetValue(key, out var flatName))
                return flatName;

            var computerName = Options.Instance.DomainController ?? GetDomainControllerForDomain(domainName);

            var result = DsGetDcName(computerName, domainName, null, null,
                (uint) (DSGETDCNAME_FLAGS.DS_IS_FLAT_NAME | DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME),
                out var pDomainControllerInfo);

            try
            {
                if (result == 0)
                {
                    var info = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(pDomainControllerInfo);
                    flatName = info.DomainName;
                }
            }
            finally
            {
                if (pDomainControllerInfo != IntPtr.Zero)
                    NetApiBufferFree(pDomainControllerInfo);
            }

            NetbiosDomainNameCache.TryAdd(key, flatName);
            return flatName;
        }


        private static string GetDomainControllerForDomain(string domainName)
        {
            var key = domainName.ToUpper();
            if (DomainControllerCache.TryGetValue(key, out var domainController))
                return domainController;

            var result = DsGetDcName(null, domainName, null, null, (uint) DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_PREFERRED,
                out var pDomainControllerInfo);

            try
            {
                if (result == 0)
                {
                    var info = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(pDomainControllerInfo);
                    domainController = info.DomainControllerName;
                }
            }
            finally
            {
                if (pDomainControllerInfo != IntPtr.Zero)
                    NetApiBufferFree(pDomainControllerInfo);
            }


            DomainControllerCache.TryAdd(key, domainController);
            return domainController;
        }

        internal static async Task<(bool success, string sid, LdapTypeEnum type)> ResolveAccountNameToSidAndType(string accountName,
            string accountDomain)
        {
            var domain = Helpers.NormalizeDomainName(accountDomain);
            var key = new UserDomainKey
            {
                AccountDomain = domain,
                AccountName = accountName
            };

            if (AppCache.GetResolvedAccount(key, out var principal))
                return (principal.ObjectIdentifier != null, principal.ObjectIdentifier, principal.ObjectType);

            var searcher = Helpers.GetDirectorySearcher(domain);
            var result = await searcher.GetOne($"(samaccountname={accountName})", ResolutionProps, SearchScope.Subtree);

            if (result == null)
            {
                AppCache.Add(key, new ResolvedPrincipal
                {
                    ObjectIdentifier = null,
                    ObjectType = LdapTypeEnum.Unknown
                });
                return (false, null, LdapTypeEnum.Unknown);
            }

            var sid = result.GetSid();
            var type = result.GetLdapType();

            AppCache.Add(key, new ResolvedPrincipal
            {
                ObjectIdentifier = sid,
                ObjectType = type
            });

            return (sid != null, sid, type);
        }

        internal static async Task<(bool success, string guid)> OUDistinguishedNameToGuid(string distinguishedName)
        {
            if (AppCache.GetResolvedDistinguishedName(distinguishedName, out var resolved))
                return (resolved.ObjectIdentifier != null, resolved.ObjectIdentifier);

            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var searcher = Helpers.GetDirectorySearcher(domain);

            var result = await searcher.GetOne("(objectclass=*)", OUGuidLookupProps, SearchScope.Base,
                distinguishedName);

            var guidBytes = result?.GetPropertyAsBytes("objectguid");
            if (guidBytes == null)
            {
                AppCache.Add(distinguishedName, new ResolvedPrincipal
                {
                    ObjectIdentifier = null,
                    ObjectType = LdapTypeEnum.OU
                });
                return (false, null);
            }

            var guid = new Guid(guidBytes).ToString().ToUpper();
            return (true, guid);
        }

        internal static async Task<(string sid, LdapTypeEnum type)> ResolveDistinguishedName(string distinguishedName)
        {
            //Check cache to see if we have the item in there first.
            if (AppCache.GetResolvedDistinguishedName(distinguishedName, out var resolved))
            {
                return (resolved.ObjectIdentifier, resolved.ObjectType);
            }

            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);

            if (distinguishedName.Contains("ForeignSecurityPrincipals"))
            {
                var sid = distinguishedName.Split(',')[0].Substring(3);
                
                if (!sid.Contains("S-1-5")) 
                    return (null, LdapTypeEnum.Unknown);

                var (finalSid, type) = await ResolveSidAndGetType(sid, domain);
                AppCache.Add(distinguishedName, new ResolvedPrincipal
                {
                    ObjectIdentifier = finalSid,
                    ObjectType = type
                });

                return (finalSid, type);
            }

            var (resolvedSid, resolvedType) = await ResolveDistinguishedNameLdap(distinguishedName);
            AppCache.Add(distinguishedName, new ResolvedPrincipal
            {
                ObjectIdentifier = resolvedSid,
                ObjectType = resolvedType
            });

            return (resolvedSid, resolvedType);
        }

        private static async Task<(string sid, LdapTypeEnum type)> ResolveDistinguishedNameLdap(
            string distinguishedName)
        {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var searcher = Helpers.GetDirectorySearcher(domain);

            var result = await searcher.GetOne("(objectclass=*)", GroupMembershipLookupProps, SearchScope.Base,
                distinguishedName);

            var sid = result.GetSid();
            var type = result.GetLdapType();

            return (sid, type);
        }

        internal static async Task<(string finalSid, LdapTypeEnum type)> ResolveSidAndGetType(string sid, string domain)
        {
            if (sid.Contains("0ACNF"))
                return (null, LdapTypeEnum.Unknown);

            if (CommonPrincipal.GetCommonSid(sid, out var commonPrincipal))
            {
                var newSid = Helpers.ConvertCommonSid(sid, domain);
                return (newSid, commonPrincipal.Type);
            }

            if (Cache.Instance.GetSidType(sid, out var type))
                return (sid, type);

            type = await LookupSidType(sid, domain);

            AppCache.Add(sid, type);
            return (sid, type);
        }

        internal static async Task<LdapTypeEnum> LookupSidType(string sid, string domain)
        {
            var hexSid = ConvertSidToHexSid(sid);
            if (hexSid == null)
                return LdapTypeEnum.Unknown;

            var resolvedDomain = await GetDomainNameFromSid(sid) ?? domain;
            var searcher = Helpers.GetDirectorySearcher(resolvedDomain);

            var result = await searcher.GetOne($"(objectsid={hexSid})", ResolutionProps, SearchScope.Subtree);

            return result?.GetLdapType() ?? LdapTypeEnum.Unknown;
        }

        private static string ConvertSidToHexSid(string sid)
        {
            try
            {
                var securityIdentifier = new SecurityIdentifier(sid);
                var sidBytes = new byte[securityIdentifier.BinaryLength];
                securityIdentifier.GetBinaryForm(sidBytes,0);
                var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
                return output;
            }
            catch
            {
                return null;
            }
        }

        private static async Task<string> GetDomainNameFromSid(string sid)
        {
            try
            {
                var securityIdentifier = new SecurityIdentifier(sid);

                var domainSid = securityIdentifier.AccountDomainSid?.Value.ToUpper();

                if (domainSid == null)
                    return null;

                if (SidToDomainNameCache.TryGetValue(domainSid, out var domainName))
                    return domainName;

                var domain = await GetDomainNameFromSidLdap(sid);

                SidToDomainNameCache.TryAdd(sid, domain);
                return domain;
            }
            catch
            {
                return null;
            }
        }

        private static async Task<string> GetDomainNameFromSidLdap(string sid)
        {
            var searcher = Helpers.GetDirectorySearcher(Options.Instance.Domain);
            var hexSid = ConvertSidToHexSid(sid);

            if (hexSid == null)
                return null;

            //Search using objectsid first
            var result = await searcher.GetOne($"(&(objectclass=domain)(objectsid={hexSid}))", new[] { "distinguishedname" }, SearchScope.Subtree, globalCatalog: true);

            if (result != null)
            {
                var domainName = Helpers.DistinguishedNameToDomain(result.DistinguishedName);
                return domainName;
            }

            //Try trusteddomain objects with the securityidentifier attribute
            result = await searcher.GetOne($"(&(objectclass=trusteddomain)(securityidentifier={sid}))",
                new[] { "cn" }, SearchScope.Subtree, globalCatalog: true);

            if (result != null)
            {
                var domainName = result.GetProperty("cn");
                return domainName;
            }

            //We didn't find anything so just return null
            return null;
        }

        private static async Task<(bool success, WorkstationInfo100 info)> CallNetWkstaGetInfo(string hostname)
        {
            if (!Helpers.CheckPort(hostname, 445))
                return (false, new WorkstationInfo100());

            var wkstaData = IntPtr.Zero;
            var netWkstaTask = Task.Run(() => NetWkstaGetInfo(hostname, 100, out wkstaData));
            if (await Task.WhenAny(Task.Delay(5000), netWkstaTask) != netWkstaTask)
                return (false, new WorkstationInfo100());

            if (netWkstaTask.Result != 0)
                return (false, new WorkstationInfo100());

            try
            {
                var wkstaInfo = Marshal.PtrToStructure<WorkstationInfo100>(wkstaData);
                return (true, wkstaInfo);
            }
            finally
            {
                if (wkstaData != IntPtr.Zero)
                    NetApiBufferFree(wkstaData);
            }
        }

        private static bool RequestNetbiosNameFromComputer(string server, string domain, out string netbios)
        {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress)) remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                {
                    //If its not an IP, we're going to try and resolve it from DNS
                    try
                    {
                        IPAddress address;
                        if (server.Contains("."))
                        {
                            address = Dns
                                .GetHostAddresses(server).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        }
                        else
                        {
                            var domainName = Options.Instance.RealDNSName ?? domain;
                            address = Dns.GetHostAddresses($"{server}.{domainName}")[0];
                        }

                        if (address == null)
                        {
                            netbios = null;
                            return false;
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    }
                    catch
                    {
                        //Failed to resolve an IP, so return null
                        netbios = null;
                        return false;
                    }
                }

                var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
                requestSocket.Bind(originEndpoint);

                try
                {
                    requestSocket.SendTo(NameRequest, remoteEndpoint);
                    var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                    if (receivedByteCount >= 90)
                    {
                        netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                        return true;
                    }

                    netbios = null;
                    return false;
                }
                catch (SocketException)
                {
                    netbios = null;
                    return false;
                }
            }
            finally
            {
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        #region NetAPI PInvoke Calls
        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint level,
            out IntPtr bufPtr);

        private struct WorkstationInfo100
        {

            public int platform_id;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string computer_name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr Buffer);
        #endregion

        #region DSGetDcName Imports
        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] GuidClass DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            uint Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [StructLayout(LayoutKind.Sequential)]
        public class GuidClass
        {
            public Guid TheGuid;
        }

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)] public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)] public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)] public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)] public string ClientSiteName;
        }

        #endregion
    }
}
