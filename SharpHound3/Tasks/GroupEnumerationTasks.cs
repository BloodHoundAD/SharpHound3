using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Timers;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

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
                    var member = await TranslateDistinguishedName(groupMemberDistinguishedName);
                    if (member.MemberId == null)
                    {
                        member.MemberId = groupMemberDistinguishedName;
                    }
                    finalMembers.Add(member);
                    count++;
                }

                timer?.Stop();
                timer?.Dispose();
            }
            else
            {
                foreach (var groupMemberDistinguishedName in groupMembers)
                {
                    var member = await TranslateDistinguishedName(groupMemberDistinguishedName);
                    if (member.MemberId == null)
                    {
                        member.MemberId = groupMemberDistinguishedName;
                    }
                    finalMembers.Add(member);
                }
            }

            group.Members = finalMembers.Distinct().ToArray();
        }

        /// <summary>
        /// Calls the appropriate TranslateDistinguishedName function depending on what options are set.
        /// Tries cache hit first
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        private static async Task<GenericMember> TranslateDistinguishedName(string distinguishedName)
        {
            //Check cache to see if we have the item in there first.
            if (AppCache.GetPrincipal(distinguishedName, out var resolved))
            {
                return new GenericMember
                {
                    MemberType = resolved.ObjectType,
                    MemberId = resolved.ObjectIdentifier
                };
            }
            var member = await TranslateDistinguishedNameWithLdap(distinguishedName);
            //Add our new member to the cache for future lookups
            AppCache.Add(distinguishedName, new ResolvedPrincipal
            {
                ObjectIdentifier = member.MemberId,
                ObjectType = member.MemberType
            });

            return member;
        }

        /// <summary>
        /// Attempts to resolve a distinguishedname to the proper format using only LDAP, allowing us to control what server it binds too.
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        private static async Task<GenericMember> TranslateDistinguishedNameWithLdap(string distinguishedName)
        {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var searcher = Helpers.GetDirectorySearcher(domain);
            SearchResultEntry searchResult;
            LdapTypeEnum type;

            if (distinguishedName.Contains("ForeignSecurityPrincipals"))
            {
                //If this is an FSP, we extract the SID from the "distinguishedname"
                var sid = distinguishedName.Split(',')[0].Substring(3);
                if (distinguishedName.Contains("CN=S-1-5-21"))
                {
                    searchResult = await searcher.GetOne($"(objectsid={Helpers.ConvertSidToHexSid(sid)})", LookupProps,
                        SearchScope.Subtree);

                    if (searchResult == null)
                    {
                        return new GenericMember
                        {
                            MemberType = LdapTypeEnum.Unknown,
                            MemberId = distinguishedName
                        };
                    }

                    type = searchResult.GetLdapType();
                    return new GenericMember
                    {
                        MemberType = type,
                        MemberId = sid
                    };
                }

                //Check if its a common principal
                if (CommonPrincipal.GetCommonSid(sid, out var commonPrincipal))
                {
                    return new GenericMember
                    {
                        MemberId = Helpers.ConvertCommonSid(sid, domain),
                        MemberType = commonPrincipal.Type
                    };
                }

                return new GenericMember{
                    MemberType = LdapTypeEnum.Unknown,
                    MemberId = sid
                };
            }

            //This is not an FSP, so lets bind to the DC and set the search base to the distinguished name
            searchResult = await searcher.GetOne("(objectclass=*)", LookupProps,
                SearchScope.Base,
                distinguishedName);

            if (searchResult == null)
            {
                return new GenericMember
                {
                    MemberId = distinguishedName,
                    MemberType= LdapTypeEnum.Unknown
                };
            }

            type = searchResult.GetLdapType();
            return new GenericMember
            {
                MemberId = searchResult.GetSid() ?? distinguishedName,
                MemberType = type
            };
        }
    }
}
