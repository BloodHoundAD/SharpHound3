using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace SharpHound3.Tasks
{
    internal class GroupEnumerationTasks
    {
        private static readonly Cache AppCache = Cache.Instance;
        internal static LdapWrapper ProcessGroupMembership(LdapWrapper wrapper)
        {
            if (wrapper is Group group)
            {
                GetGroupMembership(group);
            }

            return wrapper;
        }

        private static void GetGroupMembership(Group group)
        {
            var finalMembers = new List<GroupMember>();
            var searchResult = group.SearchResult;

            AppCache.Add(group.DistinguishedName, group.ObjectIdentifer);

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
                    
                }
            }
        }

        private static bool TranslateDistinguishedName(string distinguishedName, out string translatedName,
            out LdapTypeEnum objectType)
        {

        }
    }
}
