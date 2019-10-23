using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
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
        internal static LdapWrapper ProcessGroupMembership(LdapWrapper wrapper)
        {
            if (wrapper is Group group)
            {
                GetGroupMembership(group);
            }else if (wrapper is Computer || wrapper is User)
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

        private static void GetGroupMembership(Group group)
        {
            var finalMembers = new List<GroupMember>();
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
                //Lets try ranged retrieval here
                var searcher = Helpers.GetDirectorySearcher(group.Domain);
                var range = searcher.RetrieveRangedAttribute(group.DistinguishedName, "member");
                //If we get null back, then something went wrong.
                if (range == null)
                {
                    group.Members = finalMembers.ToArray();
                    return;
                }

                foreach (var groupMemberDistinguishedName in range)
                {
                    finalMembers.Add(TranslateDistinguishedName(groupMemberDistinguishedName));
                }
            }
            else
            {
                foreach (var groupMemberDistinguishedName in groupMembers)
                {
                    finalMembers.Add(TranslateDistinguishedName(groupMemberDistinguishedName));
                }
            }

            group.Members = finalMembers.ToArray();
        }

        /// <summary>
        /// Calls the appropriate TranslateDistinguishedName function depending on what options are set.
        /// Tries cache hit first
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        private static GroupMember TranslateDistinguishedName(string distinguishedName)
        {
            //Check cache to see if we have the item in there first.
            if (AppCache.GetPrincipal(distinguishedName, out var resolved))
            {
                return new GroupMember
                {
                    MemberType = resolved.ObjectType,
                    MemberName = resolved.ObjectIdentifier
                };
            }

            GroupMember member;

            //If a Domain Controller is specified, we want to bind specifically to that DC so we'll use that instead.
            if (Options.Instance.DomainController != null)
            {
                member = TranslateDistinguishedNameWithLdap(distinguishedName);
            }
            else
            {
                member = TranslateDistinguishedNameWithAPI(distinguishedName);
            }

            //Add our new member to the cache for future lookups
            AppCache.Add(distinguishedName, new ResolvedPrincipal
            {
                ObjectIdentifier = member.MemberName,
                ObjectType = member.MemberType
            });

            return member;
        }

        /// <summary>
        /// Translates a group member to the appropriate variables using DirectoryEntry + LookupSids. More automatic/reliable
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        private static GroupMember TranslateDistinguishedNameWithAPI(string distinguishedName)
        {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            LdapTypeEnum type;
            string sid;

            if (distinguishedName.Contains("ForeignSecurityPrincipals"))
            {
                // If the DN is a FSP, we want to extract the sid first
                sid = distinguishedName.Split(',')[0].Substring(3);

                //Check if the SID is a common principal
                if (CommonPrincipal.GetCommonSid(sid, out var commonPrincipal))
                {
                    return new GroupMember
                    {
                        MemberName = Helpers.ConvertCommonSid(sid, domain),
                        MemberType = commonPrincipal.Type
                    };
                }

                //Use the LookupAccountSid API call to get the type of the SID
                type = Helpers.LookupSidType(sid);

                return new GroupMember
                {
                    MemberType = type,
                    MemberName = sid
                };
            }

            //The DN is not a FSP, so we need to go from DistinguishedName -> SID
            //Bind to a DirectoryEntry using the DN as the path.
            using (var directoryEntry = new DirectoryEntry($"LDAP://{distinguishedName}"))
            {
                // Call RefreshCache with our array to ensure that it ONLY loads these properties.
                directoryEntry.RefreshCache(LookupProps);
                sid = directoryEntry.GetSid();

                if (sid == null)
                {
                    return new GroupMember
                    {
                        MemberType = LdapTypeEnum.Unknown,
                        MemberName = distinguishedName
                    };
                }

                type = directoryEntry.GetLdapType();

                return new GroupMember
                {
                    MemberType = type,
                    MemberName = sid
                };
            }
        }

        

        /// <summary>
        /// Attempts to resolve a distguishedname to the proper format using only LDAP, allowing us to control what server it binds too.
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        private static GroupMember TranslateDistinguishedNameWithLdap(string distinguishedName)
        {
            var domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var searcher = Helpers.GetDirectorySearcher(domain);
            SearchResultEntry searchResult;
            LdapTypeEnum type;

            if (distinguishedName.Contains("ForeignSecurityPrincipals"))
            {
                //If this is an FSP, we extract the SID for the "distinguishedname"
                var sid = distinguishedName.Split(',')[0].Substring(3);
                
                //Check if its a common principal
                if (CommonPrincipal.GetCommonSid(sid, out var commonPrincipal))
                {
                    return new GroupMember
                    {
                        MemberName = Helpers.ConvertCommonSid(sid, domain),
                        MemberType = commonPrincipal.Type
                    };
                }

                // We have a SID, so convert the sid to its hex representation and then search AD for it
                searchResult = searcher.GetOne($"(objectsid={Helpers.ConvertSidToHexSid(sid)})", LookupProps,
                    SearchScope.Subtree);

                if (searchResult == null)
                {
                    return new GroupMember
                    {
                        MemberType = LdapTypeEnum.Unknown,
                        MemberName = distinguishedName
                    };
                }

                type = searchResult.GetLdapType();
                return new GroupMember
                {
                    MemberType = type,
                    MemberName = sid
                };
            }

            //This is not an FSP, so lets bind to the DC and set the search base to the distinguished name
            searchResult = searcher.GetOne("(objectclass=*)", LookupProps,
                SearchScope.Base,
                distinguishedName);

            if (searchResult == null)
            {
                return new GroupMember
                {
                    MemberName = distinguishedName,
                    MemberType= LdapTypeEnum.Unknown
                };
            }

            type = searchResult.GetLdapType();
            return new GroupMember
            {
                MemberName = searchResult.GetSid(),
                MemberType = type
            };
        }

        
    }
}
