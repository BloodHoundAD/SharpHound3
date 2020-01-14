using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.XPath;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class GPOGroupTasks
    {
        private static readonly Regex KeyRegex = new Regex(@"(.+?)\s*=(.*)", RegexOptions.Compiled);
        private static readonly Regex MemberRegex = new Regex(@"\[Group Membership\](.*)(?:\[|$)", RegexOptions.Compiled | RegexOptions.Singleline);
        private static readonly Regex MemberLeftRegex = new Regex(@"(.*(?:S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)__Members)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemberRightRegex = new Regex(@"(S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex ExtractRid = new Regex(@"S-1-5-32-([0-9]{3})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly ConcurrentDictionary<string, List<GroupAction>> GpoActionCache = new ConcurrentDictionary<string, List<GroupAction>>();

        private static readonly (string groupName, LocalGroupRids rid)[] ValidGroupNames =
        {
            ("Administrators", LocalGroupRids.Administrators),
            ("Remote Desktop Users", LocalGroupRids.RemoteDesktopUsers),
            ("Remote Management Users", LocalGroupRids.PSRemote),
            ("Distributed COM Users", LocalGroupRids.DcomUsers)
        };

        internal static async Task<LdapWrapper> ParseGPOLocalGroups(LdapWrapper wrapper)
        {
            if (wrapper is OU || wrapper is Domain)
            {
                await ParseLinkedObject(wrapper);
            }

            return wrapper;
        }

        private static async Task ParseLinkedObject(LdapWrapper target)
        {
            var searchResultEntry = target.SearchResult;

            var gpLinks = searchResultEntry.GetProperty("gplink");

            //Check if we can get gplinks first. If not, move on, theres no point in processing further
            if (gpLinks == null)
                return;

            //First lets see if this group contains computers. If not, we'll ignore it
            var searcher = Helpers.GetDirectorySearcher(target.Domain);
            var affectedComputers = new List<string>();

            if (target is Domain testDomain && testDomain.Computers.Length > 0)
            {
                affectedComputers = new List<string>(testDomain.Computers);
            }else if (target is OU testOu && testOu.Computers.Length > 0)
            {
                affectedComputers = new List<string>(testOu.Computers);
            }
            else
            {
                foreach (var computerResult in searcher.QueryLdap("(samaccounttype=805306369)", new[] { "objectsid" },
                    SearchScope.Subtree, target.DistinguishedName))
                {
                    var sid = computerResult.GetSid();
                    if (sid == null)
                        continue;

                    affectedComputers.Add(sid);
                }
            }

            //If we have no computers, then theres no more processsing to do here.
            //Searching for computers is WAY less expensive than trying to parse the entire gplink structure first
            if (affectedComputers.Count == 0)
                return;

            var links = gpLinks.Split(']', '[').Where(link => link.StartsWith("LDAP", true, null)).ToList();
            var enforced = new List<string>();
            var unenforced = new List<string>();

            //Remove disabled links and then split enforced and unenforced links up
            foreach (var link in links)
            {
                var status = link.Split(';')[1];
                if (status == "1" || status == "3")
                    continue;

                if (status == "0")
                    unenforced.Add(link);

                if (status == "2")
                    enforced.Add(link);
            }

            //Recreate our list with enforced links in order at the end to model application order properly
            links = new List<string>();
            links.AddRange(unenforced);
            links.AddRange(enforced);

            var data = new Dictionary<LocalGroupRids, GroupResults>();
            foreach (var rid in Enum.GetValues(typeof(LocalGroupRids)))
            {
                data[(LocalGroupRids)rid] = new GroupResults();
            }

            foreach (var link in links)
            {
                var split = link.Split(';');
                var gpoDistinguishedName = split[0];
                gpoDistinguishedName =
                    gpoDistinguishedName.Substring(gpoDistinguishedName.IndexOf("CN=",
                        StringComparison.OrdinalIgnoreCase));

                if (!GpoActionCache.TryGetValue(gpoDistinguishedName, out var actions))
                {
                    actions = new List<GroupAction>();
                    var gpoDomain = Helpers.DistinguishedNameToDomain(gpoDistinguishedName);
                    var gpoResult = await searcher.GetOne("(objectclass=*)", new[] {"gpcfilesyspath"}, SearchScope.Base,
                        gpoDistinguishedName);

                    var baseFilePath = gpoResult?.GetProperty("gpcfilesyspath");

                    if (baseFilePath == null)
                    {
                        GpoActionCache.TryAdd(gpoDistinguishedName, actions);
                        continue;
                    }

                    actions.AddRange(await ProcessGPOXml(baseFilePath, gpoDomain));
                    actions.AddRange(await ProcessGPOTmpl(baseFilePath, gpoDomain));
                }

                GpoActionCache.TryAdd(gpoDistinguishedName, actions);

                if (actions.Count == 0)
                    continue;

                var restrictedMemberSets = actions.Where(x => x.Target == GroupActionTarget.RestrictedMember)
                        .Select(x => (x.TargetRid, x.TargetSid, x.TargetType)).GroupBy(x => x.TargetRid);

                foreach (var set in restrictedMemberSets)
                {
                    var results = data[set.Key];
                    var members = set.Select(x => new GenericMember
                    {
                        MemberId = x.TargetSid,
                        MemberType = x.TargetType
                    }).ToList();
                    results.RestrictedMember = members;
                    data[set.Key] = results;
                }

                var restrictedMemberOfSets = actions.Where(x => x.Target == GroupActionTarget.RestrictedMemberOf)
                    .Select(x => (x.TargetRid, x.TargetSid, x.TargetType)).GroupBy(x => x.TargetRid);

                foreach (var set in restrictedMemberOfSets)
                {
                    var results = data[set.Key];
                    var members = set.Select(x => new GenericMember
                    {
                        MemberId = x.TargetSid,
                        MemberType = x.TargetType
                    }).ToList();
                    results.RestrictedMemberOf.AddRange(members);
                    data[set.Key] = results;
                }

                var restrictedLocalGroupSets = actions.Where(x => x.Target == GroupActionTarget.LocalGroup)
                    .Select(x => (x.TargetRid, x.TargetSid, x.TargetType, x.Action)).GroupBy(x => x.TargetRid);

                foreach (var set in restrictedLocalGroupSets)
                {
                    var results = data[set.Key];
                    foreach (var (_, targetSid, targetType, action) in set)
                    {
                        var groupResults = results.LocalGroups;
                        if (action == GroupActionOperation.DeleteGroups)
                        {
                            groupResults.RemoveAll(x => x.MemberType == LdapTypeEnum.Group);
                        }

                        if (action == GroupActionOperation.DeleteUsers)
                        {
                            groupResults.RemoveAll(x => x.MemberType == LdapTypeEnum.User);
                        }

                        if (action == GroupActionOperation.Add)
                        {
                            groupResults.Add(new GenericMember
                            {
                                MemberType = targetType,
                                MemberId = targetSid
                            });
                        }

                        if (action == GroupActionOperation.Delete)
                        {
                            groupResults.RemoveAll(x => x.MemberId == targetSid);
                        }

                        data[set.Key].LocalGroups = groupResults;
                    }
                }
            }

            var affectsComputers = false;

            if (target is Domain domain)
            {
                foreach (var x in data)
                {
                    var restrictedMember = x.Value.RestrictedMember;
                    var restrictedMemberOf = x.Value.RestrictedMemberOf;
                    var groupMember = x.Value.LocalGroups;
                    var finalMembers = new List<GenericMember>();
                    if (restrictedMember.Count > 0)
                    {
                        finalMembers.AddRange(restrictedMember);
                        finalMembers.AddRange(restrictedMemberOf);
                    }
                    else
                    {
                        finalMembers.AddRange(restrictedMemberOf);
                        finalMembers.AddRange(groupMember);
                    }

                    finalMembers = finalMembers.Distinct().ToList();
                    if (finalMembers.Count > 0)
                        affectsComputers = true;

                    switch (x.Key)
                    {
                        case LocalGroupRids.Administrators:
                            domain.LocalAdmins = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.RemoteDesktopUsers:
                            domain.RemoteDesktopUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.DcomUsers:
                            domain.DcomUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.PSRemote:
                            domain.PSRemoteUsers = finalMembers.ToArray();
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }

                if (affectsComputers && domain.Computers.Length == 0)
                    domain.Computers = affectedComputers.ToArray();
            }

            if (target is OU ou)
            {
                foreach (var x in data)
                {
                    var restrictedMember = x.Value.RestrictedMember;
                    var restrictedMemberOf = x.Value.RestrictedMemberOf;
                    var groupMember = x.Value.LocalGroups;
                    var finalMembers = new List<GenericMember>();
                    if (restrictedMember.Count > 0)
                    {
                        finalMembers.AddRange(restrictedMember);
                        finalMembers.AddRange(restrictedMemberOf);
                    }
                    else
                    {
                        finalMembers.AddRange(restrictedMemberOf);
                        finalMembers.AddRange(groupMember);
                    }

                    finalMembers = finalMembers.Distinct().ToList();
                    if (finalMembers.Count > 0)
                        affectsComputers = true;

                    switch (x.Key)
                    {
                        case LocalGroupRids.Administrators:
                            ou.LocalAdmins = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.RemoteDesktopUsers:
                            ou.RemoteDesktopUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.DcomUsers:
                            ou.DcomUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.PSRemote:
                            ou.PSRemoteUsers = finalMembers.ToArray();
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }

                if (affectsComputers && ou.Computers.Length == 0)
                    ou.Computers = affectedComputers.ToArray();
            }
        }

        private static async Task<List<GroupAction>> ProcessGPOTmpl(string basePath, string gpoDomain)
        {
            var actions = new List<GroupAction>();
            var templatePath = $"{basePath}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf";

            if (File.Exists(templatePath))
            {
                using (var reader = new StreamReader(new FileStream(templatePath, FileMode.Open, FileAccess.Read)))
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
                                if (Enum.IsDefined(typeof(LocalGroupRids), rid))
                                {
                                    foreach (var member in val.Split(','))
                                    {

                                        var (success, sid, type) = await GetSid(member.Trim('*'), gpoDomain);
                                        if (!success)
                                            continue;
                                        actions.Add(new GroupAction
                                        {
                                            Target = GroupActionTarget.RestrictedMember,
                                            Action = GroupActionOperation.Add,
                                            TargetSid = sid,
                                            TargetType = type,
                                            TargetRid = (LocalGroupRids)rid
                                        });
                                    }
                                }
                                
                            }

                            //Scenario 2: A group has been set as memberOf to one of our local groups
                            var index = key.IndexOf("MemberOf", StringComparison.CurrentCultureIgnoreCase);
                            if (rightMatches.Count > 0 && index > 0)
                            {
                                var sid = key.Trim('*').Substring(0, index - 3).ToUpper();
                                var type= LdapTypeEnum.Unknown;
                                if (!sid.StartsWith("S-1-5", StringComparison.OrdinalIgnoreCase))
                                {
                                    var (success, aSid, lType) = await ResolutionHelpers.ResolveAccountNameToSidAndType(sid, gpoDomain);
                                    if (!success)
                                    {
                                        (success, aSid, lType) = await ResolutionHelpers.ResolveAccountNameToSidAndType($"{sid}$", gpoDomain);
                                        sid = !success ? null : aSid;
                                    }
                                    else
                                        sid = aSid;

                                    type = lType;
                                }

                                if (sid == null || !sid.StartsWith("S-1-5", StringComparison.OrdinalIgnoreCase))
                                    continue;

                                
                                foreach (var match in rightMatches)
                                {
                                    var rid = int.Parse(ExtractRid.Match(match.ToString()).Groups[1].Value);
                                    if (!Enum.IsDefined(typeof(LocalGroupRids), rid)) continue;
                                    
                                    var targetGroup = (LocalGroupRids) rid;
                                    actions.Add(new GroupAction
                                    {
                                        Target = GroupActionTarget.RestrictedMemberOf,
                                        Action = GroupActionOperation.Add,
                                        TargetRid = targetGroup,
                                        TargetSid = sid,
                                        TargetType = type
                                    });
                                }
                            }
                        }
                    }
                }
            }

            return actions;
        }

        private static async Task<List<GroupAction>> ProcessGPOXml(string basePath, string gpoDomain)
        {
            var actions = new List<GroupAction>();
            var xmlPath = $"{basePath}\\MACHINE\\Preferences\\Groups\\Groups.xml";
            if (File.Exists(xmlPath))
            {
                var doc = new XPathDocument(xmlPath);
                var navigator = doc.CreateNavigator();
                var groupsNodes = navigator.Select("/Groups");
                while (groupsNodes.MoveNext())
                {
                    var disabled = groupsNodes.Current.GetAttribute("disabled", "") == "1";
                    if (disabled)
                        continue;

                    var groupNodes = groupsNodes.Current.Select("Group");
                    while (groupNodes.MoveNext())
                    {
                        var groupProperties = groupNodes.Current.Select("Properties");
                        while (groupProperties.MoveNext())
                        {
                            var currentProperties = groupProperties.Current;
                            var action = currentProperties.GetAttribute("action", "");
                            //We only want to look at action = update, because the other ones dont work on Built In groups
                            if (!action.Equals("u", StringComparison.OrdinalIgnoreCase))
                                continue;

                            var groupSid = currentProperties.GetAttribute("groupSid", "");
                            var groupName = currentProperties.GetAttribute("groupName", "");
                            LocalGroupRids? targetGroup = null;

                            //Determine the group we're targetting
                            //Try to use the groupSid first
                            if (!string.IsNullOrEmpty(groupSid))
                            {
                                var sidMatch = ExtractRid.Match(groupSid);
                                if (sidMatch.Success)
                                {
                                    var rid = int.Parse(sidMatch.Groups[1].Value);
                                    if (Enum.IsDefined(typeof(LocalGroupRids), rid))
                                        targetGroup = (LocalGroupRids)rid;
                                }
                            }

                            //If that fails, try to use the groupName
                            if (targetGroup == null)
                            {
                                if (!string.IsNullOrEmpty(groupName))
                                {
                                    var group = ValidGroupNames.FirstOrDefault(g =>
                                        g.groupName.Equals(groupName, StringComparison.OrdinalIgnoreCase));

                                    if (group != default)
                                    {
                                        targetGroup = group.rid;
                                    }
                                }
                            }

                            //We failed to resolve a group to target so continue
                            if (targetGroup == null)
                                continue;

                            var deleteUsers = currentProperties.GetAttribute("deleteAllUsers", "") == "1";
                            var deleteGroups = currentProperties.GetAttribute("deleteAllGroups", "") == "1";

                            if (deleteUsers)
                            {
                                actions.Add(new GroupAction
                                {
                                    Action = GroupActionOperation.DeleteUsers,
                                    Target = GroupActionTarget.LocalGroup,
                                    TargetRid = (LocalGroupRids) targetGroup
                                });
                            }

                            if (deleteGroups)
                            {
                                actions.Add(new GroupAction
                                {
                                    Action = GroupActionOperation.DeleteGroups,
                                    Target = GroupActionTarget.LocalGroup,
                                    TargetRid = (LocalGroupRids)targetGroup
                                });
                            }

                            var members = currentProperties.Select("Members/Member");

                            while (members.MoveNext())
                            {
                                var memberAction = members.Current.GetAttribute("action", "").Equals("ADD", StringComparison.CurrentCulture) ? GroupActionOperation.Add : GroupActionOperation.Delete;
                                var memberName = members.Current.GetAttribute("name", "");
                                var memberSid = members.Current.GetAttribute("sid", "");
                                LdapTypeEnum memberType;

                                if (!string.IsNullOrEmpty(memberSid))
                                {
                                    memberType = await ResolutionHelpers.LookupSidType(memberSid, gpoDomain);

                                    actions.Add(new GroupAction
                                    {
                                        Action = memberAction,
                                        Target = GroupActionTarget.LocalGroup,
                                        TargetSid = memberSid,
                                        TargetType = memberType,
                                        TargetRid = (LocalGroupRids)targetGroup
                                    });
                                    continue;
                                }

                                if (!string.IsNullOrEmpty(memberName))
                                {
                                    if (memberName.Contains("\\"))
                                    {
                                        var splitMember = memberName.Split('\\');
                                        memberName = splitMember[1];
                                        var memberDomain = splitMember[0];
                                        var (success, lookupSid, lType) =
                                            await ResolutionHelpers.ResolveAccountNameToSidAndType(memberName, memberDomain);


                                        if (success)
                                        {
                                            actions.Add(new GroupAction
                                            {
                                                Action = memberAction,
                                                Target = GroupActionTarget.LocalGroup,
                                                TargetSid = lookupSid,
                                                TargetType = lType,
                                                TargetRid = (LocalGroupRids)targetGroup
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return actions;
        }

        private static async Task<(bool success, string sid, LdapTypeEnum type)> GetSid(string element, string domainName)
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

                user = user.ToUpper();

                //Try to resolve as a user object first
                var (success, sid, type) = await ResolutionHelpers.ResolveAccountNameToSidAndType(user, domain);
                
                if (!success)
                {
                    //Resolution failed, so try as a computer objectnow
                    (success, sid, type) = await ResolutionHelpers.ResolveAccountNameToSidAndType($"{user}$", domain);

                    //Its not a computer either so just return null
                    if (!success)
                        return (false, null, LdapTypeEnum.Unknown);
                }

                return (true, sid, type);
            }
            
            //The element is just a sid, so return it straight
            var lType = await ResolutionHelpers.LookupSidType(element, domainName);
            return (true, element, lType);
        }

        private class TempStorage
        {
            internal int GroupRID { get; set; }
            internal string MemberSid { get; set; }
            internal LdapTypeEnum MemberType { get; set; }
        }

        private class GroupAction
        {
            internal GroupActionOperation Action { get; set; }
            internal GroupActionTarget Target { get; set; }
            internal string TargetSid { get; set; }
            internal LdapTypeEnum TargetType { get; set; }
            internal LocalGroupRids TargetRid { get; set; }

            public override string ToString()
            {
                return $"{nameof(Action)}: {Action}, {nameof(Target)}: {Target}, {nameof(TargetSid)}: {TargetSid}, {nameof(TargetType)}: {TargetType}, {nameof(TargetRid)}: {TargetRid}";
            }
        }

        public class GroupResults
        {
            public List<GenericMember> RestrictedMemberOf = new List<GenericMember>();
            public List<GenericMember> RestrictedMember = new List<GenericMember>();
            public List<GenericMember> LocalGroups = new List<GenericMember>();
        }

        private enum GroupActionOperation
        {
            Add,
            Delete,
            DeleteUsers,
            DeleteGroups
        }

        private enum GroupActionTarget
        {
            RestrictedMemberOf,
            RestrictedMember,
            LocalGroup
        }
    }
}
