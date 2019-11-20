using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Heijden.DNS;
using SharpHound3.Enums;
using SharpHound3.Producers;
using SharpHound3.Tasks;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;

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
        private static readonly ConcurrentDictionary<string, Resolver> DNSResolverCache = new ConcurrentDictionary<string, Resolver>();
        private static readonly ConcurrentDictionary<string, string> SidToDomainNameCache = new ConcurrentDictionary<string, string>();
        private static readonly ConcurrentDictionary<string, bool> PingCache = new ConcurrentDictionary<string, bool>();
        private static readonly Random RandomGen = new Random();
        private static readonly CancellationTokenSource CancellationTokenSource = new CancellationTokenSource();
        private static readonly Regex DCReplaceRegex = new Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        internal static readonly string[] ResolutionProps = {"samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname"};

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
        private static readonly Regex SPNRegex = new Regex(@".*\/.*", RegexOptions.Compiled);
        private static readonly string ProcStartTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        private static string _currentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";

        internal static CancellationToken GetCancellationToken()
        {
            return CancellationTokenSource.Token;
        }

        internal static void InvokeCancellation()
        {
            CancellationTokenSource.Cancel();
        }

        internal static void StartNewRun()
        {
            PingCache.Clear();
            _currentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        }

        internal static string ConvertSidToHexSid(string sid)
        {
            var securityIdentifier = new SecurityIdentifier(sid);
            var sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0);

            var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
            return output;
        }

        internal static string DistinguishedNameToDomain(string distinguishedName)
        {
            var temp = distinguishedName.Substring(distinguishedName.IndexOf("DC=",
                StringComparison.CurrentCultureIgnoreCase));
            temp = DCReplaceRegex.Replace(temp, "").Replace(",", ".").ToUpper();
            return temp;
        }

        internal static string GetForestName(string domain=null)
        {
            try
            {
                if (domain == null)
                    return Forest.GetCurrentForest().Name;

                var domainObject = Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, domain));
                return domainObject.Forest.Name;
            }
            catch
            {
                return domain;
            }
            
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
            var key = NormalizeDomainName(domain) ?? NullKey;
            if (DirectorySearchMap.TryGetValue(key, out var searcher))
                return searcher;

            searcher = new DirectorySearch(key);
            DirectorySearchMap.TryAdd(key, searcher);
            return searcher;
        }

        internal static async Task<string> TryResolveHostToSid(string hostname, string domain)
        {
            //Uppercase for consistency
            var newHostname = hostname.ToUpper();
            //Convert SPN values to a basic hostname
            newHostname = SPNToHost(newHostname);
            //Strip $ signs
            newHostname = newHostname.TrimEnd('$');
            var normalizedDomainName = NormalizeDomainName(domain);

            if (HostResolutionMap.TryGetValue(newHostname, out var resolvedHost)) return resolvedHost;

            string computerName;
            string computerDomain = null;
            if (!IPAddress.TryParse(newHostname, out _))
            {
                // Assume we got a hostname in the format PRIMARY.testlab.local
                if (newHostname.Contains("."))
                {
                    var splitName = newHostname.Split('.');
                    computerName = splitName[0];
                    computerDomain = string.Join(".", splitName.Skip(1));
                }
                //Assume we just got the netbios name. Like PRIMARY
                else
                {
                    computerName = newHostname;
                    computerDomain = domain ?? normalizedDomainName;
                }

                var (success, sid) = await AccountNameToSid(computerName, computerDomain, true);
                if (success)
                {
                    HostResolutionMap.TryAdd(newHostname, sid);
                    return sid;
                }
            }

            //Call NetWkstaGetInfo and see if we can get the info from there.
            if (CheckPort(newHostname, 445) && CallNetWkstaGetInfo(newHostname, out var workstationInfo))
            {
                computerDomain = workstationInfo.lan_group;
                computerName = workstationInfo.computer_name;

                //Try converting Computer Name to SID
                var (success, sid) = await AccountNameToSid(computerName, computerDomain, true);
                if (success)
                {
                    HostResolutionMap.TryAdd(newHostname, sid);
                    return sid;
                }
            }

            if (RequestNetbiosNameFromComputer(newHostname, domain, out computerName))
            {
                //Lets try and use computerDomain if it was set by another method previously, it might be more accurate than what we passed into the function
                //If computerDomain is still null, then set it to our current domain name
                computerDomain = computerDomain ?? normalizedDomainName;

                var (success, sid) = await AccountNameToSid(computerName, computerDomain, true);
                if (success)
                {
                    HostResolutionMap.TryAdd(newHostname, sid);
                    return sid;
                }
            }

            // Attempt to fall back to DNS
            var resolver = GetDNSResolver(domain);
            if (resolver != null)
            {
                if (IPAddress.TryParse(newHostname, out var ipAddress))
                {
                    //Try to turn IPv6 into an IPv4 via DNS
                    if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        var addresses = await Dns.GetHostAddressesAsync(ipAddress.ToString());
                        ipAddress = addresses.DefaultIfEmpty(ipAddress).FirstOrDefault(addr => addr.AddressFamily == AddressFamily.InterNetwork);
                    }

                    var query = resolver.Query(Resolver.GetArpaFromIp(ipAddress), QType.PTR);
                    if (query.RecordsPTR.Length > 0)
                    {
                        var resolved = query.RecordsPTR[0].ToString().TrimEnd('.');
                        var splitName = resolved.Split('.');
                        computerName = splitName[0];
                        computerDomain = string.Join(".", splitName.Skip(1));

                        var (success, sid) = await AccountNameToSid(computerName, computerDomain, true);
                        if (success)
                        {
                            HostResolutionMap.TryAdd(newHostname, sid);
                            return sid;
                        }
                    }
                }
                else
                {
                    var query = resolver.Query($"{newHostname}.{NormalizeDomainName(domain)}", QType.A);
                    if (query.RecordsA.Length > 0)
                    {
                        var resolved = query.RecordsA[0].RR.NAME.TrimEnd('.');
                        var splitName = resolved.Split('.');
                        computerName = splitName[0];
                        computerDomain = string.Join(".", splitName.Skip(1));

                        var (success, sid) = await AccountNameToSid(computerName, computerDomain, true);
                        if (success)
                        {
                            HostResolutionMap.TryAdd(newHostname, sid);
                            return sid;
                        }
                    }
                }
            }
            else
            {
                if (IPAddress.TryParse(newHostname, out var ipAddress))
                {
                    var entries = await Dns.GetHostEntryAsync(ipAddress);
                    (computerDomain, computerName) = SplitComputerName(entries.HostName);
                    var (success, sid) = await AccountNameToSid(computerName, computerDomain, true);
                    if (success)
                    {
                        HostResolutionMap.TryAdd(newHostname, sid);
                        return sid;
                    }
                }
                else
                {
                    var entries = await Dns.GetHostEntryAsync(newHostname);
                    (computerDomain, computerName) = SplitComputerName(entries.HostName);
                    var (success, sid) = await AccountNameToSid(computerName, computerDomain, true);
                    if (success)
                    {
                        HostResolutionMap.TryAdd(newHostname, sid);
                        return sid;
                    }
                }
            }
            

            //Everything has failed. Life is sad. Just return the hostname, not much else to do here
            computerName = computerName ?? newHostname;
            computerDomain = computerDomain ?? normalizedDomainName;

            //If we already have a dot in the name, assume its a hostname of some kind and just return that
            if (computerName.Contains("."))
            {
                HostResolutionMap.TryAdd(newHostname, computerName);
                return computerName;
            }
            
            //Take our original normalized domain, and return host@domain
            computerName = $"{computerName}.{computerDomain}";
            HostResolutionMap.TryAdd(newHostname, computerName);
            return computerName;
        }

        private static string SPNToHost(string target)
        {
            return SPNRegex.IsMatch(target) ? target.Split('/')[1].Split(':')[0] : target;
        }

        private static (string name, string domain) SplitComputerName(string name)
        {
            if (!name.Contains(".")) 
                return (name, null);

            var splitName = name.Split('.');
            return (splitName[0], string.Join(".", splitName.Skip(1)));

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
                            var domainName = Options.Instance.RealDNSName ?? domain ?? NormalizeDomainName(null);
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
            }
            finally
            {
                //Make sure we close the socket if its open
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
                    var forest = GetForestName(domain);
                    OutputTasks.SeenCommonPrincipals.TryAdd(forest, sid);
                    return $"{forest}-{sid}".ToUpper();
                }

                var nDomain = NormalizeDomainName(domain);
                OutputTasks.SeenCommonPrincipals.TryAdd(nDomain, sid);
                return $"{nDomain}-{sid}";
            }

            return sid;
        }

        internal static async Task<(bool success, string sid)> AccountNameToSid(string accountName,
            string accountDomain)
        {
            if (Cache.Instance.GetPrincipal(accountName, out var principal))
            {
                var sid = principal.ObjectIdentifier;
                return (sid != null, sid);
            }

            var domainName = NormalizeDomainName(accountDomain);
            (bool success, string sid) result;
            if (Options.Instance.DomainController != null)
            {
                result = await AccountNameToSidLdap(accountName, domainName);
            }
            else
            {
                result = AccountNameToSidApi(accountName, domainName);
            }

            if (result.success)
            {
                Cache.Instance.Add(accountName, new ResolvedPrincipal
                {
                    ObjectIdentifier = result.sid,
                    ObjectType = LdapTypeEnum.User
                });

                return result;
            }

            var computerAccountName = $"{accountName}$";
            if (Options.Instance.DomainController != null)
            {
                result = await AccountNameToSidLdap(computerAccountName, domainName);
            }
            else
            {
                result = AccountNameToSidApi(computerAccountName, domainName);
            }

            Cache.Instance.Add(accountName, new ResolvedPrincipal
            {
                ObjectIdentifier = result.sid,
                ObjectType = LdapTypeEnum.Computer
            });

            return result;
        }

        internal static async Task<(bool success, string sid)> AccountNameToSid(string accountName, string accountDomain, bool isComputer)
        {
            if (isComputer)
            {
                accountName = $"{accountName}$";
            }

            string sid;
            if (Cache.Instance.GetPrincipal(accountName, out var principal))
            {
                sid = principal.ObjectIdentifier;
                return (sid != null, sid);
            }

            var domainName = NormalizeDomainName(accountDomain);
            (bool result, string sid) result;
            if (Options.Instance.DomainController != null)
            {
                result = await AccountNameToSidLdap(accountName, domainName);
            }
            else
            {
                result = AccountNameToSidApi(accountName, domainName);
            }

            Cache.Instance.Add(accountName, new ResolvedPrincipal
            {
                ObjectIdentifier = result.sid,
                ObjectType = isComputer ? LdapTypeEnum.Computer : LdapTypeEnum.User
            });

            return result;
        }

        private static async Task<(bool success, string sid)> AccountNameToSidLdap(string accountName, string accountDomain)
        {
            var searcher = GetDirectorySearcher(accountDomain);

            var result = await searcher.GetOne($"(samaccountname={accountName.ToUpper()})", ResolutionProps,
                SearchScope.Subtree);

            string sid;
            if (result == null)
            {
                return (false, null);
            }

            sid = result.GetObjectIdentifier();
            return (sid != null, sid);
        }

        private static (bool success, string sid) AccountNameToSidApi(string accountName, string accountDomain)
        {
            try
            {
                var account = new NTAccount($"{accountDomain}\\{accountName}");
                var translated = account.Translate(typeof(SecurityIdentifier));
                var sid = translated.Value.ToUpper();
                return (true, sid);
            }
            catch
            {
                return (false, null);
            }
        }

        internal static async Task<(bool success, string guid)> DistinguishedNameToGuid(string distinguishedName)
        {
            if (Cache.Instance.GetPrincipal(distinguishedName, out var resolved))
            {
                return (resolved.ObjectIdentifier != null, resolved.ObjectIdentifier);
            }

            (bool success, string guid) result;
            if (Options.Instance.DomainController != null)
                result = await DistinguishedNameToGuidLdap(distinguishedName);
            else
                result = DistinguishedNameToGuidTranslateName(distinguishedName);

            Cache.Instance.Add(distinguishedName, new ResolvedPrincipal
            {
                ObjectIdentifier = result.guid,
                ObjectType = LdapTypeEnum.OU
            });

            return result;
        }

        private static async Task<(bool success, string guid)> DistinguishedNameToGuidLdap(string dn)
        {
            var domain = DistinguishedNameToDomain(dn);
            var searcher = GetDirectorySearcher(domain);

            var result = await searcher.GetOne("(objectclass=*)", new[] {"objectguid"}, SearchScope.Base, dn);
            if (result == null)
            {
                return (false, null);
            }

            var guidBytes = result.GetPropertyAsBytes("objectguid");
            if (guidBytes == null)
            {
                return (false, null);
            }

            var guid = new Guid(guidBytes).ToString().ToUpper();
            return (true, guid);
        }

        private static (bool success, string guid) DistinguishedNameToGuidTranslateName(string dn)
        {
            var translated = new StringBuilder(1024);
            var nameSize = translated.Capacity;
            var status = TranslateName(dn, EXTENDED_NAME_FORMAT.NameFullyQualifiedDN, EXTENDED_NAME_FORMAT.NameUniqueId,
                translated, ref nameSize);

            if (status != 0)
            {
                return (true, translated.ToString());
            }

            return (false, null);
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
                if (server.ToString().StartsWith("fec0")) 
                    continue;

                newServerList.Add(server);
                break;
            }

            resolver.DnsServers = newServerList.ToArray();
            DNSResolverCache.TryAdd(key, resolver);
            return resolver;
        }

        private static string FindDomainDNSServer(string domain)
        {
            foreach (var dc in BaseProducer.GetDomainControllers())
            {
                var result = dc.Value;
                var dcName = result.GetProperty("samaccountname").TrimEnd('$');

                if (CheckHostPort($"{dcName}.{domain}", 53))
                {
                    return dcName;
                }
            }

            return null;
        }

        internal static async Task DoDelay()
        {
            var opts = Options.Instance;
            if (opts.Throttle == 0)
                return;

            if (opts.Jitter == 0)
            {
                await Task.Delay(opts.Throttle);
                return;
            }

            var percent = (int) Math.Floor((double) (opts.Jitter * (opts.Throttle / 100)));
            var delay = opts.Throttle + RandomGen.Next(-percent, percent);
            await Task.Delay(delay);
        }

        internal static bool CheckPort(string hostname, int port)
        {
            if (Options.Instance.SkipPortScan)
                return true;

            var key = $"{hostname}-{port}".ToUpper();
            if (PingCache.TryGetValue(key, out var portOpen)) return portOpen;

            portOpen = CheckHostPort(hostname, port);
            PingCache.TryAdd(key, portOpen);
            return portOpen;
        }

        private static bool CheckHostPort(string hostname, int port)
        {
            using (var client = new TcpClient())
            {
                try
                {
                    var result = client.BeginConnect(hostname, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(Options.Instance.PortScanTimeout);
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

        internal static string NormalizeDomainName(string domain)
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

        internal static async Task<LdapTypeEnum> LookupSidType(string sid)
        {
            if (CommonPrincipal.GetCommonSid(sid, out var principal))
                return principal.Type;

            if (Cache.Instance.GetSidType(sid, out var type))
                return type;

            if (Options.Instance.DomainController != null)
            {
                type = await LookupSidTypeLdap(sid);
            }
            else
            {
                type = LookupSidTypeAPI(sid);
            }

            Cache.Instance.Add(sid, type);

            return type;
        }

        private static async Task<LdapTypeEnum> LookupSidTypeLdap(string sid)
        {
            var hexSid = ConvertSidToHexSid(sid);
            var domain = await GetDomainNameFromSid(sid);

            var searcher = GetDirectorySearcher(domain);

            var result = await searcher.GetOne($"(objectsid={hexSid})", ResolutionProps, SearchScope.Subtree);
            return result?.GetLdapType() ?? LdapTypeEnum.Unknown;
        }

        /// <summary>
        /// Uses the LookupAccountSid function to attempt to get the type of a sid
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        private static LdapTypeEnum LookupSidTypeAPI(string sid)
        {
            var name = new StringBuilder();
            var nameLength = (uint)name.Capacity;
            var referencedDomain = new StringBuilder();
            var domainLength = (uint)referencedDomain.Capacity;

            var securityIdentifier = new SecurityIdentifier(sid);
            var sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0);

            var error = 0;
            if (!LookupAccountSid(null, sidBytes, name, ref nameLength, referencedDomain, ref domainLength, out var type))
            {
                error = Marshal.GetLastWin32Error();
                if (error == 122)
                {
                    name.EnsureCapacity((int)nameLength);
                    referencedDomain.EnsureCapacity((int)domainLength);
                    error = 0;
                    if (!LookupAccountSid(null, sidBytes, name, ref nameLength, referencedDomain, ref domainLength,
                        out type))
                    {
                        error = Marshal.GetLastWin32Error();
                    }
                }
            }

            if (error != 0) return LdapTypeEnum.Unknown;
            switch (type)
            {
                case SID_NAME_USE.SidTypeComputer:
                    return LdapTypeEnum.Computer;
                case SID_NAME_USE.SidTypeGroup:
                    return LdapTypeEnum.Group;
                case SID_NAME_USE.SidTypeUser:
                    return LdapTypeEnum.User;
                default:
                    return LdapTypeEnum.Unknown;
            }
        }

        internal static async Task<string> GetDomainNameFromSid(string sid)
        {
            SecurityIdentifier identifier;
            try
            {
                identifier = new SecurityIdentifier(sid);
            }
            catch
            {
                return null;
            }

            if (identifier.AccountDomainSid == null)
            {
                return null;
            }

            var domainSid = identifier.AccountDomainSid.Value.ToUpper();

            if (SidToDomainNameCache.TryGetValue(domainSid, out var domainName))
            {
                return domainName;
            }

            if (Options.Instance.DomainController != null)
                return await GetDomainNameFromSidLdap(sid);

            return GetDomainNameFromSidAPI(sid);
        }

        /// <summary>
        /// Attempts to get the domain name for a SID using LDAP from the Global Catalog
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        private static async Task<string> GetDomainNameFromSidLdap(string sid)
        {
            var searcher = GetDirectorySearcher(null);

            var hexSid = ConvertSidToHexSid(sid);

            //Search using objectsid first
            var result = await searcher.GetOne($"(&(objectclass=domain)(objectsid={hexSid}))", new[] {"distinguishedname"}, SearchScope.Subtree, globalCatalog:true);

            if (result != null)
            {
                var domainName = DistinguishedNameToDomain(result.DistinguishedName);
                SidToDomainNameCache.TryAdd(sid, domainName);
                return domainName;
            }

            //Try trusteddomain objects with the securityidentifier attribute
            result = await searcher.GetOne($"(&(objectclass=trusteddomain)(securityidentifier={sid}))",
                new[] {"cn"}, SearchScope.Subtree, globalCatalog: true);

            if (result != null)
            {
                var domainName = result.GetProperty("cn");
                SidToDomainNameCache.TryAdd(sid, domainName);
                return domainName;
            }

            //We didn't find anything so just return null
            SidToDomainNameCache.TryAdd(sid, null);
            return null;
        }

        private static string GetDomainNameFromSidAPI(string sid)
        {
            var name = new StringBuilder();
            var nameLength = (uint)name.Capacity;
            var referencedDomain = new StringBuilder();
            var domainLength = (uint)referencedDomain.Capacity;

            var securityIdentifier = new SecurityIdentifier(sid);
            var sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0);

            var error = 0;
            if (!LookupAccountSid(null, sidBytes, name, ref nameLength, referencedDomain, ref domainLength, out var type))
            {
                error = Marshal.GetLastWin32Error();
                if (error == 122)
                {
                    name.EnsureCapacity((int)nameLength);
                    referencedDomain.EnsureCapacity((int)domainLength);
                    error = 0;
                    if (!LookupAccountSid(null, sidBytes, name, ref nameLength, referencedDomain, ref domainLength,
                        out type))
                    {
                        error = Marshal.GetLastWin32Error();
                    }
                }
            }

            if (error != 0)
            {
                SidToDomainNameCache.TryAdd(sid, null);
                return null;
            }

            var domainName = NormalizeDomainName(referencedDomain.ToString());
            SidToDomainNameCache.TryAdd(sid, domainName);
            return domainName;
        }

        internal static string GetLoopFileName()
        {
            var options = Options.Instance;
            var finalFilename = options.ZipFilename == null ? "BloodHoundLoopResults.zip" : $"{options.ZipFilename}.zip";
            
            if (options.RandomizeFilenames)
            {
                finalFilename = $"{Path.GetRandomFileName()}.zip";
            }

            finalFilename = $"{ProcStartTime}_{finalFilename}";

            if (options.OutputPrefix != null)
            {
                finalFilename = $"{options.OutputPrefix}_{finalFilename}";
            }

            var finalPath = Path.Combine(options.OutputDirectory, finalFilename);

            return finalPath;
        }

        internal static string ResolveFileName(string filename, string extension, bool addTime)
        {
            var finalFilename = filename;
            if (!filename.EndsWith(extension))
                finalFilename = $"{filename}.{extension}";

            if ((extension == "json" || extension == "zip") && Options.Instance.RandomizeFilenames)
            {
                finalFilename = $"{Path.GetRandomFileName()}.{extension}";
            }

            if (addTime)
            {
                finalFilename = $"{_currentLoopTime}_{finalFilename}";
            }

            if (Options.Instance.OutputPrefix != null)
            {
                finalFilename = $"{Options.Instance.OutputPrefix}_{finalFilename}";
            }

            var finalPath = Path.Combine(Options.Instance.OutputDirectory, finalFilename);

            return finalPath;
        }

        internal static string Base64(string input)
        {
            var plainBytes = System.Text.Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(plainBytes);
        }


        #region NetAPI PInvoke Calls
        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaGetInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            uint level,
            out IntPtr bufPtr);

        #pragma warning disable 649
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
        #pragma warning restore 649

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

        #region LookupAccountSid

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            System.Text.StringBuilder lpName,
            ref uint cchName,
            System.Text.StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);

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
