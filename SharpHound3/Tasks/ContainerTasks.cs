using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class ContainerTasks
    {
        internal static async Task<LdapWrapper> EnumerateContainer(LdapWrapper wrapper)
        {
            if (wrapper is OU ou)
            {
                await ProcessOUObject(ou);
            }else if (wrapper is Domain domain)
            {
                await ProcessDomainObject(domain);
            }

            return wrapper;
        }

        private static async Task ProcessDomainObject(Domain domain)
        {
            var searchResult = domain.SearchResult;
            var resolvedLinks = new List<GPLink>();

            var gpLinks = searchResult.GetProperty("gplink");

            if (gpLinks != null)
            {
                foreach (var link in gpLinks.Split(']', '[').Where(l => l.StartsWith("LDAP")))
                {
                    var splitLink = link.Split(';');
                    var distinguishedName = splitLink[0];
                    distinguishedName =
                        distinguishedName.Substring(distinguishedName.IndexOf("CN=", StringComparison.OrdinalIgnoreCase));

                    var status = splitLink[1];

                    //Status 1 and status 3 correspond to disabled/unenforced and disabled/enforced, so filter them out
                    if (status == "1" || status == "3")
                        continue;

                    //If the status is 0, its unenforced, 2 is enforced
                    var enforced = status == "2";

                    var (success, guid) = await ResolutionHelpers.OUDistinguishedNameToGuid(distinguishedName);
                    if (success)
                    {
                        resolvedLinks.Add(new GPLink
                        {
                            IsEnforced = enforced,
                            Guid = guid
                        });
                    }
                }
            }

            var users = new List<string>();
            var computers = new List<string>();
            var ous = new List<string>();

            var searcher = Helpers.GetDirectorySearcher(domain.Domain);
            foreach (var containedObject in searcher.QueryLdap(
                "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))", Helpers.ResolutionProps, SearchScope.OneLevel, domain.DistinguishedName))
            { 
                var type = containedObject.GetLdapType();

                var id = containedObject.GetObjectIdentifier();
                if (id == null)
                    continue;

                switch (type)
                {
                    case LdapTypeEnum.OU:
                        ous.Add(id);
                        break;
                    case LdapTypeEnum.Computer:
                        computers.Add(id);
                        break;
                    case LdapTypeEnum.User:
                        users.Add(id);
                        break;
                    default:
                        continue;
                }
            }

            foreach (var containedObject in searcher.QueryLdap("(objectclass=container)", Helpers.ResolutionProps,
                SearchScope.OneLevel, domain.DistinguishedName))
            {
                var type = containedObject.GetLdapType();
                var id = containedObject.GetObjectIdentifier();
                if (id == null)
                    continue;

                switch (type)
                {
                    case LdapTypeEnum.OU:
                        ous.Add(id);
                        break;
                    case LdapTypeEnum.Computer:
                        computers.Add(id);
                        break;
                    case LdapTypeEnum.User:
                        users.Add(id);
                        break;
                    default:
                        continue;
                }
            }

            domain.Computers = computers.ToArray();
            domain.Users = users.ToArray();
            domain.ChildOus = ous.ToArray();
            domain.Links = resolvedLinks.ToArray();
        }

        private static async Task ProcessOUObject(OU ou)
        {
            var searchResult = ou.SearchResult;
            var gpOptions = searchResult.GetProperty("gpoptions");

            ou.Properties.Add("blocksinheritance", gpOptions != null && gpOptions == "1");

            var resolvedLinks = new List<GPLink>();

            var gpLinks = searchResult.GetProperty("gplink");
            if (gpLinks != null)
            {
                foreach (var link in gpLinks.Split(']', '[').Where(l => l.StartsWith("LDAP")))
                {
                    var splitLink = link.Split(';');
                    var distinguishedName = splitLink[0];
                    distinguishedName =
                        distinguishedName.Substring(distinguishedName.IndexOf("CN=", StringComparison.OrdinalIgnoreCase));
                    var status = splitLink[1];

                    //Status 1 and status 3 correspond to disabled/unenforced and disabled/enforced, so filter them out
                    if (status == "1" || status == "3")
                        continue;

                    //If the status is 0, its unenforced, 2 is enforced
                    var enforced = status == "2";

                    var (success, guid) = await ResolutionHelpers.OUDistinguishedNameToGuid(distinguishedName);
                    if (success)
                    {
                        resolvedLinks.Add(new GPLink
                        {
                            IsEnforced = enforced,
                            Guid = guid
                        });
                    }
                }
            }

            var users = new List<string>();
            var computers = new List<string>();
            var ous = new List<string>();

            var searcher = Helpers.GetDirectorySearcher(ou.Domain);
            foreach (var containedObject in searcher.QueryLdap(
                "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
                Helpers.ResolutionProps, SearchScope.OneLevel, ou.DistinguishedName))
            {
                var type = containedObject.GetLdapType();

                var id = containedObject.GetObjectIdentifier();
                if (id == null)
                    continue;

                switch (type)
                {
                    case LdapTypeEnum.OU:
                        ous.Add(id);
                        break;
                    case LdapTypeEnum.Computer:
                        computers.Add(id);
                        break;
                    case LdapTypeEnum.User:
                        users.Add(id);
                        break;
                    default:
                        continue;
                }
            }

            ou.Computers = computers.ToArray();
            ou.Users = users.ToArray();
            ou.ChildOus = ous.ToArray();
            ou.Links = resolvedLinks.ToArray();
        }
    }
}
