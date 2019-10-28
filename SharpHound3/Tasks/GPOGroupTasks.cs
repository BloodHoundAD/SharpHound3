using System;
using System.CodeDom;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.XPath;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;
using Group = System.Text.RegularExpressions.Group;

namespace SharpHound3.Tasks
{
    internal class GPOGroupTasks
    {
        private static readonly Regex KeyRegex = new Regex(@"(.+?)\s*=(.*)", RegexOptions.Compiled);
        private static readonly Regex MemberRegex = new Regex(@"\[Group Membership\](.*)(?:\[|$)", RegexOptions.Compiled | RegexOptions.Singleline);
        private static readonly Regex MemberLeftRegex = new Regex(@"(.*(?:S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)__Members)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemberRightRegex = new Regex(@"(S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex ExtractRid = new Regex(@"S-1-5-32-([0-9]{3})", RegexOptions.Compiled);
        private static ConcurrentDictionary<string, List<(string ouDistinguishedName, bool enabled)>> OuGPLinkCache = null;
        internal static void BuildOuGplinkCache(string domain)
        {
            if (OuGPLinkCache == null)
                OuGPLinkCache = new ConcurrentDictionary<string, List<(string ouGuid, bool enabled)>>();
            var searcher = Helpers.GetDirectorySearcher(domain);

            foreach (var ou in searcher.QueryLdap("(&(objectclass=organizationalunit)(gplink=*))", new[] {"gplink"},
                SearchScope.Subtree))
            {
                var gpLinks = ou.GetProperty("gplink");
                var ouDistinguishedName = ou.DistinguishedName;

                //Split the GPLinks up on the OU and start parsing them
                foreach (var link in gpLinks.Split(']', '[').Where(l => l.StartsWith("LDAP")))
                {
                    var splitLink = link.Split(';');
                    var status = splitLink[1];
                    var gpoDistinguishedName = splitLink[0];
                    gpoDistinguishedName =
                        gpoDistinguishedName.Substring(gpoDistinguishedName.IndexOf("CN=", StringComparison.OrdinalIgnoreCase));

                    var enabled = !(status == "1" || status == "3");
                    OuGPLinkCache.AddOrUpdate(gpoDistinguishedName.ToUpper(), new List<(string ouDistinguishedName, bool enabled)> {(ouDistinguishedName, enabled)}, 
                        (s, list) =>
                        {
                            list.Add((ouDistinguishedName, enabled));
                            return list;
                        });
                }
            }
        }
        internal static async Task<LdapWrapper> ParseGPOLocalGroups(LdapWrapper wrapper)
        {
            if (wrapper is GPO gpo)
            {
                await ParseGPO(gpo);
            }

            return wrapper;
        }

        private static async Task ParseGPO(GPO gpo)
        {
            var searchResultEntry = gpo.SearchResult;
            var filePath = searchResultEntry.GetProperty("gpcfilesyspath");

            if (filePath == null)
                return;

            var resolvedList = new List<TempStorage>();
            var templatePath = $"{filePath}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf";

            //Parse GptTmpl files
            if (File.Exists(templatePath))
            {
                using (var reader = new StreamReader(new FileStream(templatePath, FileMode.Open)))
                {
                    var content = await reader.ReadToEndAsync();
                    var memberMatch = MemberRegex.Match(content);

                    if (memberMatch.Success)
                    {
                        var memberText = memberMatch.Groups[1].Value;
                        var memberLines = Regex.Split(memberText.Trim(), @"\r\n|\r|\n");

                        foreach (var memberLine in memberLines)
                        {
                            var keyMatch = KeyRegex.Match(memberLine);

                            var key = keyMatch.Groups[1].Value.Trim();
                            var val = keyMatch.Groups[2].Value.Trim();

                            var leftMatch = MemberLeftRegex.Match(key);
                            var rightMatches = MemberRightRegex.Matches(val);

                            //Scenario 1: Members of a local group are explicitly set
                            if (leftMatch.Success)
                            {
                                var extracted = ExtractRid.Match(leftMatch.Value);
                                var rid = int.Parse(extracted.Groups[1].Value);
                                foreach (var member in val.Split(','))
                                {
                                    var (success, sid) = await GetSid(member.Trim('*'), gpo.Domain);
                                    if (!success)
                                        continue;
                                    var type = await Helpers.LookupSidType(sid);
                                    resolvedList.Add(new TempStorage{
                                        GroupRID = rid,
                                        MemberSid = sid,
                                        MemberType = type
                                    });
                                }
                            }

                            //Secnario 2: A group has been set as memberOf to one of our local groups
                            var index = key.IndexOf("MemberOf", StringComparison.CurrentCultureIgnoreCase);
                            if (rightMatches.Count > 0 && index > 0)
                            {
                                var sid = key.Trim('*').Substring(0, index - 3);
                                var type = await Helpers.LookupSidType(sid);

                                foreach (var match in rightMatches)
                                {
                                    var rid = int.Parse(ExtractRid.Match(match.ToString()).Groups[1].Value);
                                    resolvedList.Add(new TempStorage
                                    {
                                        MemberType = type,
                                        GroupRID = rid,
                                        MemberSid = sid
                                    });
                                }
                            }
                        }
                    }
                }
            }

            var xmlPath = $"{filePath}\\MACHINE\\Preferences\\Groups\\Groups.xml";
            if (File.Exists(xmlPath))
            {
                Console.WriteLine(xmlPath);
                var doc = new XPathDocument(xmlPath);
                var navigator = doc.CreateNavigator();
                var groupNodes = navigator.Select("/Groups/Group");

                while (groupNodes.MoveNext())
                {
                    var properties = groupNodes.Current.Select("Properties");
                    while (properties.MoveNext())
                    {
                        var groupSid = properties.Current.GetAttribute("groupSid", "");
                        if (string.IsNullOrEmpty(groupSid))
                            continue;

                        var sidMatch = ExtractRid.Match(groupSid);
                        if (!sidMatch.Success)
                            continue;

                        var rid = int.Parse(sidMatch.Groups[1].Value);

                        if (!Enum.IsDefined(typeof(LocalGroupRids), rid))
                            continue;

                        var members = properties.Current.Select("Members");
                        while (members.MoveNext())
                        {
                            var member = members.Current.Select("Member");
                            while (member.MoveNext())
                            {
                                var action = member.Current.GetAttribute("action", "");
                                if (action == "ADD")
                                {
                                    var sid = member.Current.GetAttribute("sid", "");
                                    if (string.IsNullOrEmpty(sid))
                                        continue;

                                    var type = await Helpers.LookupSidType(sid);
                                    resolvedList.Add(new TempStorage
                                    {
                                        GroupRID = rid,
                                        MemberSid = sid,
                                        MemberType = type
                                    });
                                }
                            }
                        }
                    }
                }
            }

            Console.WriteLine(resolvedList.Count);
            //If we dont have any objects set for some reason, just move on, this GPO is done processing.
            if (resolvedList.Count == 0)
                return;

            //Next we need to determine what computers are affected by this GPO
            var searcher = Helpers.GetDirectorySearcher(gpo.Domain);
            var dn = gpo.DistinguishedName;
            var affectedComputers = new List<string>();

            //Check our cache first, this is a huge performance plus
            if (OuGPLinkCache.TryGetValue(dn.ToUpper(), out var cache))
            {
                // Loop over each OU this GPO is linked too
                foreach (var (ouDistinguishedName, enabled) in cache)
                {
                    //If the GPLink isn't enabled, just ignore it
                    if (!enabled)
                        continue;

                    Console.WriteLine($"{ouDistinguishedName} enabled");
                    //Get the computers in the OU
                    foreach (var computer in searcher.QueryLdap("(samaccounttype=805306369)", new[] {"objectsid"},
                        SearchScope.Subtree, ouDistinguishedName))
                    {
                        Console.WriteLine(computer.DistinguishedName);
                        var computerSid = computer.GetSid();
                        if (computerSid != null)
                            affectedComputers.Add(computerSid);
                    }
                }
            }
            else
            {
                Console.WriteLine("Missed cache");
                //This shouldn't happen, but its here as a backup
                foreach (var linkedOu in searcher.QueryLdap($"(&(objectclass=organizationalUnit)(gplink=*{dn}*))",
                    new[] {"distinguishedname"}, SearchScope.Subtree))
                {
                    var ouDistinguishedName = linkedOu.DistinguishedName;

                    foreach (var computer in searcher.QueryLdap("(samaccounttype=805306369)", new[] {"objectsid"},
                        SearchScope.Subtree, ouDistinguishedName))
                    {
                        var computerSid = computer.GetSid();
                        if (computerSid != null)
                            affectedComputers.Add(computerSid);
                    }
                }
            }

            //If we dont have any computers this GPO affects, just move on
            if (affectedComputers.Count == 0)
                return;

            var finalAffectedComputers = affectedComputers.Distinct().ToArray();
            gpo.AffectedComputers = finalAffectedComputers;

            //Use LINQ to create our final arrays
            gpo.LocalAdmins = resolvedList.Where((x) => x.GroupRID == (int) LocalGroupRids.Administrators).Select((x) =>
                new GenericMember
                {
                    MemberType = LdapTypeEnum.Computer,
                    MemberId = x.MemberSid
                }).ToArray();

            gpo.DcomUsers = resolvedList.Where((x) => x.GroupRID == (int)LocalGroupRids.DcomUsers).Select((x) =>
                new GenericMember
                {
                    MemberType = LdapTypeEnum.Computer,
                    MemberId = x.MemberSid
                }).ToArray();

            gpo.RemoteDesktopUsers = resolvedList.Where((x) => x.GroupRID == (int)LocalGroupRids.RemoteDesktopUsers).Select((x) =>
                new GenericMember
                {
                    MemberType = LdapTypeEnum.Computer,
                    MemberId = x.MemberSid
                }).ToArray();

            gpo.PSRemoteUsers = resolvedList.Where((x) => x.GroupRID == (int)LocalGroupRids.PSRemote).Select((x) =>
                new GenericMember
                {
                    MemberType = LdapTypeEnum.Computer,
                    MemberId = x.MemberSid
                }).ToArray();
        }

        private static async Task<(bool success, string sid)> GetSid(string element, string domainName)
        {
            if (!element.StartsWith("S-1-", StringComparison.CurrentCulture))
            {
                string user;
                string domain;
                if (element.Contains('\\'))
                {
                    //The account is in the format DOMAIN\\username
                    var split = element.Split('\\');
                    domain = split[0];
                    user = split[1];
                }
                else
                {
                    //The account is just a username, so try with the current domain
                    domain = domainName;
                    user = element;
                }

                //Try to resolve as a user object first
                var (success, rSid) = await Helpers.AccountNameToSid(user, domain, false);

                if (!success)
                {
                    //Resolution failed, so try as a computer objectnow
                    (success, rSid) = await Helpers.AccountNameToSid(user, domain, true);
                    //Its not a computer either so just return null
                    if (!success)
                        return (false, null);
                }

                return (true, rSid);
            }
            
            //The element is just a sid, so return it straight
            return (true, element);
        }

        private class TempStorage
        {
            internal int GroupRID { get; set; }
            internal string MemberSid { get; set; }
            internal LdapTypeEnum MemberType { get; set; }
        }
    }
}
