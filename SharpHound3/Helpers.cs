using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Heijden.DNS;

namespace SharpHound3
{
    internal class Helpers
    {
        private const string NullKey = "NULLDOMAIN";
        private static readonly HashSet<string> Groups = new HashSet<string> { "268435456", "268435457", "536870912", "536870913" };
        private static readonly HashSet<string> Computers = new HashSet<string> { "805306369" };
        private static readonly HashSet<string> Users = new HashSet<string> { "805306368" };
        private static readonly ConcurrentDictionary<string, DirectorySearch> DirectorySearchMap = new ConcurrentDictionary<string, DirectorySearch>();
        private static readonly ConcurrentDictionary<string, string> HostResolutionMap = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, Domain> DomainObjectMap = new ConcurrentDictionary<string, Domain>();
        private static readonly ConcurrentDictionary<string, string> DomainNetbiosMap = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, string> AccountNameToSidCache = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, Resolver> DNSResolverCache = new ConcurrentDictionary<string, Resolver>();
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
        private static Regex SPNRegex = new Regex(@".*\/.*", RegexOptions.Compiled);

        internal static string DistinguishedNameToDomain(string distinguishedName)
        {
            return distinguishedName.Substring(distinguishedName.IndexOf("DC=", StringComparison.CurrentCulture)).Replace("DC=", "").Replace(",", ".").ToUpper();
        }

        internal static string GetForestName(string domain=null)
        {
            if (domain == null)
                return Forest.GetCurrentForest().Name;

            var domainObject = Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, domain));
            return domainObject.Forest.Name;
        }

        internal static LdapTypeEnum SamAccountTypeToType(string samAccountType)
        {
            if (Groups.Contains(samAccountType))
                return LdapTypeEnum.Group;

            if (Users.Contains(samAccountType))
                return LdapTypeEnum.User;

            if (Computers.Contains(samAccountType))
                return LdapTypeEnum.Computer;

            return LdapTypeEnum.Unknown;
        }

        internal static DirectorySearch GetDirectorySearcher(string domain)
        {
            var key = NormalizeDomainName(domain);
            if (DirectorySearchMap.TryGetValue(key, out var searcher))
                return searcher;

            searcher = new DirectorySearch(key);
            DirectorySearchMap.TryAdd(key, searcher);
            return searcher;
        }

        internal static string ResolveHostToValue(string hostname, string domain)
        {
            //Upcase for consistency
            var newHostName = hostname.ToUpper();
            
            //Turn SPNs into just the hostname portion
            var parsedHost = SPNToHost(newHostName);

            //Check our cache for a resolution already
            if (HostResolutionMap.TryGetValue(parsedHost, out var resolvedHostName)) return resolvedHostName;

            string computerDomain;
            string computerNetbios;

            //If we have an IP address the next bit of logic is useless
            if (!IPAddress.TryParse(parsedHost, out _))
            {
                //Turn a DNS name into potentially a computer name + domain
                if (parsedHost.Contains("."))
                {
                    var splitName = parsedHost.Split('.');
                    computerNetbios = splitName[0];
                    computerDomain = GetDomainNetbiosName(String.Join(".", splitName.Skip(1)));
                }
                else
                {
                    //Assume the domain is the same as the one passed in
                    computerDomain = GetDomainNetbiosName(domain);
                    computerNetbios = parsedHost;
                }

                //Try and resolve the 
                if (AccountNameToSid($"{computerDomain}\\{computerNetbios}", out var sid))
                {
                    HostResolutionMap.TryAdd(parsedHost, sid);
                    return sid;
                }
            }

            //Call NetWkstaGetInfo and see if the computer will give us a netbios name/domain
            if (CallNetWkstaGetInfo(parsedHost, out var workstationInfo))
            {
                //If we got the info, turning this into a real account should be simple
                computerDomain = workstationInfo.lan_group.ToUpper();
                computerNetbios = workstationInfo.computer_name;

                if (AccountNameToSid($"{computerDomain}\\{computerNetbios}", out var sid))
                {
                    HostResolutionMap.TryAdd(parsedHost, sid);
                    return sid;
                }

                //Sid resolution failed, so just return a normalized name
                computerDomain = NormalizeDomainName(computerDomain);
                var fullName = $"{computerNetbios}.{computerDomain}".ToUpper();
                HostResolutionMap.TryAdd(parsedHost, fullName);
                return fullName;
            }

            // Next try requesting the Netbios name from the computer using a UDP packet
            if (RequestNetbiosNameFromComputer(parsedHost, out computerNetbios))
            {
                //We succeeded, so we'll assume the domain is the one we're enumerating from. Attempt to convert to a SID
                computerDomain = GetDomainNetbiosName(domain);
                if (AccountNameToSid($"{computerDomain}\\{computerNetbios}", out var sid))
                {
                    HostResolutionMap.TryAdd(hostname, sid);
                    return sid;
                }

                //Sid resolution failed, so just return a normalized name
                computerDomain = NormalizeDomainName(computerDomain);
                var fullName = $"{computerNetbios}.{computerDomain}".ToUpper();
                HostResolutionMap.TryAdd(parsedHost, fullName);
                return fullName;
            }

            // Fallback to DNS
            var resolver = GetDNSResolver(domain);
            // If the host is an IP address, attempt to query a PTR
            if (IPAddress.TryParse(parsedHost, out var ip))
            {
                var query = resolver.Query(Resolver.GetArpaFromIp(ip), QType.PTR);
                if (query.RecordsPTR.Length > 0)
                {
                    var resolved = query.RecordsPTR[0].ToString().TrimEnd('.');
                    HostResolutionMap.TryAdd(parsedHost, resolved);
                    return resolved;
                }
            }
            else
            {
                //Host is not an IP, so look for the A record and return the result of that
                var query = resolver.Query($"{parsedHost}.{NormalizeDomainName(domain)}", QType.A);
                if (query.RecordsA.Length > 0)
                {
                    var resolved  = query.RecordsA[0].RR.NAME.TrimEnd('.');
                    HostResolutionMap.TryAdd(parsedHost, resolved);
                    return resolved;
                }
            }

            //Everything else has failed. Life is sad. If the hostname contains a . assume its already an FQDN and return it
            if (parsedHost.Contains("."))
            {
                HostResolutionMap.TryAdd(parsedHost, parsedHost);
                return parsedHost;
            }

            //Just take the hostname and tack the domain name on at the end. Truly the last fallback.
            var possibleName = $"{parsedHost}.{NormalizeDomainName(domain)}";
            HostResolutionMap.TryAdd(parsedHost, possibleName);
            return possibleName;
        }

        private static string SPNToHost(string target)
        {
            return SPNRegex.IsMatch(target) ? target.Split('/')[1].Split(':')[0] : target;
        }

        private static bool RequestNetbiosNameFromComputer(string server, out string netbios)
        {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            //Set receive timeout to 1 second
            requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
            EndPoint remoteEndpoint;
            if (IPAddress.TryParse(server, out var parsedAddress)) remoteEndpoint = new IPEndPoint(parsedAddress, 137);
            else
            {
                var address = Dns.GetHostAddresses(server)[0];
                remoteEndpoint = new IPEndPoint(address, 137);
            }

            var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
            requestSocket.Bind(originEndpoint);
            requestSocket.SendTo(NameRequest, remoteEndpoint);

            try
            {
                var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                if (receivedByteCount >= 90)
                {
                    netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim();
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
            finally
            {
                requestSocket.Close();
            }
        }

        /// <summary>
        /// Prepends a common sid with the domain prefix, or just returns the sid back
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <returns>Prepended SID or same sid</returns>
        internal static string ConvertCommonSid(string sid, string domain)
        {
            if (CommonPrincipal.GetCommonSid(sid, out _))
            {
                if (sid == "S-1-5-9")
                {
                    return $"{GetForestName(domain)}-{sid}";
                }
                return $"{NormalizeDomainName(domain)}-{sid}";
            }

            return sid;
        }

        internal static bool AccountNameToSid(string accountName, out string sid)
        {
            if (AccountNameToSidCache.TryGetValue(accountName, out sid))
                return sid != null;

            try
            {
                var account = new NTAccount(accountName);
                var translated = account.Translate(typeof(SecurityIdentifier));
                sid = translated.Value;
                return true;
            }
            catch
            {
                AccountNameToSidCache.TryAdd(accountName, null);
                return false;
            }
        }


        internal static bool DistinguishedNameToGuid(string distinguishedName, out string guid)
        {
            if (AccountNameToSidCache.TryGetValue(distinguishedName, out guid))
                return guid != null;

            // Placeholder for options.DomainController set
            if (false)
            {

            }
            else
            {
                return DistinguishedNameToGuidTranslateName(distinguishedName, out guid);
            }
        }

        private static bool DistinguishedNameToGuidLdap(string dn, out string guid)
        {
            var domain = DistinguishedNameToDomain(dn);
            var searcher = GetDirectorySearcher(domain);

            var result = searcher.QueryLdap("(&)", new[] {"objectguid"}, SearchScope.Base, dn).DefaultIfEmpty(null).FirstOrDefault();
            if (result == null)
            {
                guid = null;
                return false;
            }

            var guidBytes = result.GetPropertyAsBytes("objectguid");
            if (guidBytes == null)
            {
                guid = null;
                return false;
            }

            guid = new Guid(guidBytes).ToString();
            return true;
        }

        private static bool DistinguishedNameToGuidTranslateName(string dn, out string guid)
        {
            var translated = new StringBuilder(1024);
            var nameSize = translated.Capacity;
            var status = TranslateName(dn, EXTENDED_NAME_FORMAT.NameFullyQualifiedDN, EXTENDED_NAME_FORMAT.NameUniqueId,
                translated, ref nameSize);

            if (status != 0)
            {
                guid = translated.ToString();
                return true;
            }

            guid = null;
            return false;
        }

        internal static bool AccountNameToSid(string username, string domain, out string sid)
        {
            var netbios = GetDomainNetbiosName(domain);
            var accountName = $"{netbios}\\{username}";

            if (AccountNameToSidCache.TryGetValue(accountName, out sid))
                return sid != null;

            try
            {
                var account = new NTAccount(accountName);
                var translated = account.Translate(typeof(SecurityIdentifier));
                sid = translated.Value;
                return true;
            }
            catch
            {
                AccountNameToSidCache.TryAdd(accountName, null);
                return false;
            }
        }

        private static string GetDomainNetbiosName(string domain)
        {
            var key = NormalizeDomainName(domain);
            if (DomainNetbiosMap.TryGetValue(key, out var netBios))
                return netBios;

            var returnValue = DsGetDcName(null, key, 0, null,
                DSGETDCNAME_FLAGS.DS_IS_DNS_NAME | DSGETDCNAME_FLAGS.DS_RETURN_FLAT_NAME, out var domainControllerInfo);

            try
            {
                if (returnValue != 0)
                    return null;

                var info = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(domainControllerInfo, typeof(DOMAIN_CONTROLLER_INFO));
                DomainNetbiosMap.TryAdd(key, info.DomainName);
                return info.DomainName;
            }
            finally
            {
                if (domainControllerInfo != IntPtr.Zero)
                    NetApiBufferFree(domainControllerInfo);
            }
        }

        /// <summary>
        /// Gets a DNS Resolver for a domain, pointing DNS to a DC with port 53 open
        /// </summary>
        /// <param name="domain"></param>
        /// <returns>Resolver</returns>
        private static Resolver GetDNSResolver(string domain)
        {
            var domainName = NormalizeDomainName(domain);
            var key = domainName ?? NullKey;

            if (DNSResolverCache.TryGetValue(key, out var resolver))
                return resolver;

            // Create a new resolver object which will auto populate with our local nameservers
            resolver = new Resolver();
            var newServerList = new List<IPEndPoint>();

            // Try to find a DC in our target domain that has 53 open
            var dnsServer = FindDomainDNSServer(domainName);
            if (dnsServer != null)
            {
                // Resolve the DC to an IP and add it to our nameservers
                var query = resolver.Query(dnsServer, QType.A);
                if (query.RecordsA.Length > 0)
                    newServerList.Add(new IPEndPoint(query.RecordsA[0].Address, 53));
            }

            // Add the first local dns server that isn't a VMware one to our list
            foreach (var server in resolver.DnsServers)
            {
                if (!server.ToString().StartsWith("fec0"))
                {
                    newServerList.Add(server);
                    break;
                }
            }

            resolver.DnsServers = newServerList.ToArray();
            DNSResolverCache.TryAdd(key, resolver);
            return resolver;
        }

        private static string FindDomainDNSServer(string domain)
        {
            var domainObj = GetDomainObject(domain);

            foreach (DomainController dc in domainObj.FindAllDomainControllers())
            {
                if (CheckHostPort(dc.Name, 53))
                {
                    return dc.Name;
                }
            }

            return null;
        }

        private static bool CheckHostPort(string hostname, int port)
        {
            using (var client = new TcpClient())
            {
                try
                {
                    var result = client.BeginConnect(hostname, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne();
                    if (!success) return false;

                    client.EndConnect(result);
                }
                catch
                {
                    return false;
                }

                return true;
            }
        }

        private static string NormalizeDomainName(string domain)
        {
            var dObj = GetDomainObject(domain);
            return dObj?.Name.ToUpper();
        }

        private static Domain GetDomainObject(string domain)
        {
            var key = domain ?? NullKey;
            if (DomainObjectMap.TryGetValue(key, out var domainObj))
                return domainObj;

            try
            {
                if (key == NullKey)
                    domainObj = Domain.GetCurrentDomain();
                else
                {
                    var context = new DirectoryContext(DirectoryContextType.Domain, domain);
                    domainObj = Domain.GetDomain(context);
                }

                DomainObjectMap.TryAdd(key, domainObj);
                return domainObj;
            }
            catch
            {
                DomainObjectMap.TryAdd(key, null);
                return domainObj;
            }
        }

        private static bool CallNetWkstaGetInfo(string hostname, out WorkstationInfo100 wkstaInfo)
        {
            var wkstaData = IntPtr.Zero;

            var netWkstaTask = Task.Run(() => NetWkstaGetInfo(hostname, 100, out wkstaData));

            var success = netWkstaTask.Wait(TimeSpan.FromSeconds(3));
            try
            {
                if (!success || netWkstaTask.Result != 0)
                {
                    wkstaInfo = new WorkstationInfo100();
                    return false;
                }

                wkstaInfo = (WorkstationInfo100) Marshal.PtrToStructure(wkstaData, typeof(WorkstationInfo100));
                return true;
            }
            finally
            {
                if (wkstaData != IntPtr.Zero)
                {
                    NetApiBufferFree(wkstaData);
                }
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

        #region DsGetDcName

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            [MarshalAs(UnmanagedType.U4)]
            DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [Flags]
        private enum DSGETDCNAME_FLAGS : uint
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
        private struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        #endregion

        #region TranslateName

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int TranslateName(string accountName, EXTENDED_NAME_FORMAT accountNameFormat,
            EXTENDED_NAME_FORMAT desiredFormat, StringBuilder translatedName, ref int userNameSize);

        private enum EXTENDED_NAME_FORMAT : int
        {
            /// <summary>
            /// Unknown Name Format
            /// </summary>
            NameUnknown = 0,
            /// <summary>
            /// DistinguishedName Format
            /// CN=Jeff Smith,OU=Users,DC=Engineering,DC=Microsoft,DC=Com
            /// </summary>
            NameFullyQualifiedDN = 1,
            NameSamCompatible = 2, //Engineering\JSmith
            NameDisplay = 3, //Jeff Smith
            /// <summary>
            /// ObjectGUID
            /// {4fa050f0-f561-11cf-bdd9-00aa003a77b6}
            /// </summary>
            NameUniqueId = 6,
            NameCanonical = 7, //engineering.microsoft.com/software/someone
            NameUserPrincipal = 8, //someone@example.com
            NameCanonicalEx = 9, //engineering.microsoft.com/software\nJSmith
            NameServicePrincipal = 10, //www/www.microsoft.com@microsoft.com
            /// <summary>
            /// DnsDomain Format
            /// DOMAIN\SamAccountName
            /// </summary>
            NameDnsDomain = 12

        }
        #endregion

        #region LookupAccountName

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupAccountName(string systemName, string accountName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint sidLength, StringBuilder domainName,
            ref uint domainNameLength, out SID_NAME_USE type);
        
        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }
        #endregion
    }
}
