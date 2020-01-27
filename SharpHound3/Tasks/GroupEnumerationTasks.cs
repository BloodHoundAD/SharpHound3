using System;
using System.Collections.Generic;
using System.Linq;
using System.Timers;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class GroupEnumerationTasks
    {
        private static readonly Cache AppCache = Cache.Instance;
        //These are the properties required to do the appropriate lookups for group membership translations
        internal static readonly string[] LookupProps = { "samaccounttype", "objectsid", "objectclass" };

        internal static async Task<LdapWrapper> ProcessGroupMembership(LdapWrapper wrapper)
        {
            if (wrapper is Group group)
            {
                await GetGroupMembership(group);
            }
            else if (wrapper is Computer || wrapper is User)
            {
                GetPrimaryGroupInfo(wrapper);
            }

            return wrapper;
        }

        private static void GetPrimaryGroupInfo(LdapWrapper wrapper)
        {
            var primaryGroupId = wrapper.SearchResult.GetProperty("primarygroupid");
            if (primaryGroupId == null)
                return;
            var domainSid = wrapper.ObjectIdentifier.Substring(0, wrapper.ObjectIdentifier.LastIndexOf("-", StringComparison.Ordinal));
            var primaryGroupSid = $"{domainSid}-{primaryGroupId}";

            if (wrapper is Computer c)
            {
                c.PrimaryGroupSid = primaryGroupSid;
            }
            else if (wrapper is User u)
            {
                u.PrimaryGroupSid = primaryGroupSid;
            }
        }

        private static async Task GetGroupMembership(Group group)
        {
            var finalMembers = new List<GenericMember>();
            var searchResult = group.SearchResult;

            AppCache.Add(group.DistinguishedName, new ResolvedPrincipal
            {
                ObjectIdentifier = group.ObjectIdentifier,
                ObjectType = LdapTypeEnum.Group
            });

            var groupMembers = searchResult.GetPropertyAsArray("member");

            //If we get 0 back for member length, its either a ranged retrieval issue, or its an empty group.
            if (groupMembers.Length == 0)
            {
                Timer timer = null;
                var count = 0;
                //Lets try ranged retrieval here
                var searcher = Helpers.GetDirectorySearcher(group.Domain);
                var range = await searcher.RangedRetrievalAsync(group.DistinguishedName, "member");
                //If we get null back, then something went wrong.
                if (range == null)
                {
                    group.Members = finalMembers.ToArray();
                    return;
                }

                if (range.Count > 1000 && Options.Instance.Verbose)
                {
                    timer = new Timer(30000);
                    timer.Elapsed += (sender, args) =>
                    {
                        Console.WriteLine($"Group Enumeration - {group.DisplayName} {count} / {range.Count}");
                    };
                    timer.AutoReset = true;
                    timer.Start();
                }

                foreach (var groupMemberDistinguishedName in range)
                {
                    var (sid, type) = await ResolutionHelpers.ResolveDistinguishedName(groupMemberDistinguishedName);
                    if (sid == null)
                        sid = groupMemberDistinguishedName;

                    finalMembers.Add(new GenericMember
                    {
                        MemberId = sid,
                        MemberType = type
                    });
                    count++;
                }

                timer?.Stop();
                timer?.Dispose();
            }
            else
            {
                foreach (var groupMemberDistinguishedName in groupMembers)
                {
                    var (sid, type) = await ResolutionHelpers.ResolveDistinguishedName(groupMemberDistinguishedName);
                    if (sid == null)
                        sid = groupMemberDistinguishedName;

                    finalMembers.Add(new GenericMember
                    {
                        MemberId = sid,
                        MemberType = type
                    });
                }
            }

            group.Members = finalMembers.Distinct().ToArray();
        }
    }
}
