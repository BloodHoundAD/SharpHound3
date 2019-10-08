using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using BHECollector.LdapWrappers;

namespace BHECollector.Tasks
{
    internal static class FindType
    {
        internal static LdapWrapper FindLdapType(SearchResultEntry searchResultEntry)
        {
            //Look for a null DN first. Not sure why this would happen.
            var distinguishedName = searchResultEntry.DistinguishedName;
            if (distinguishedName == null)
                return null;

            var accountName = searchResultEntry.GetProp("samaccountname");
            var samAccountType = searchResultEntry.GetProp("samaccounttype");
            var accountDomain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var objectSid = searchResultEntry.GetSid();
            var objectType = LdapTypeEnum.Unknown;

            LdapWrapper wrapper;

            //Lets see if its a "common" principal
            if (CommonPrincipal.GetCommonSid(objectSid, out var commonPrincipal))
            {
                accountName = commonPrincipal.Name;
                objectType = commonPrincipal.Type;
            }
            else
            {
                //Its not a common principal. Lets use properties to figure out what it actually is
                if (samAccountType != null)
                {
                    if (samAccountType == "805306370")
                        return null;

                    objectType = Helpers.SamAccountTypeToType(samAccountType);
                }
                else
                {
                    var objectClasses = searchResultEntry.GetPropArray("objectClass");
                    if (objectClasses == null)
                    {
                        objectType = LdapTypeEnum.Unknown;
                    }else if (objectClasses.Contains("groupPolicyContainer"))
                    {
                        objectType = LdapTypeEnum.GPO;
                    }
                    else if (objectClasses.Contains("organizationalUnit"))
                    {
                        objectType = LdapTypeEnum.OU;
                    }
                    else if (objectClasses.Contains("domain"))
                    {
                        objectType = LdapTypeEnum.Domain;
                    }
                }
            }

            //Depending on the object type, create the appropriate wrapper object
            switch (objectType)
            {
                case LdapTypeEnum.Computer:
                    accountName = accountName?.TrimEnd('$');
                    wrapper = new Computer(searchResultEntry)
                    {
                        DisplayName = $"{accountName}.{accountDomain}"
                    };
                    break;
                case LdapTypeEnum.User:
                    wrapper = new User(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}"
                    };
                    break;
                case LdapTypeEnum.Group:
                    wrapper = new Group(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}"
                    };
                    break;
                case LdapTypeEnum.GPO:
                    accountName = searchResultEntry.GetProp("displayname");
                    wrapper = new GPO(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}"
                    };
                    break;
                case LdapTypeEnum.OU:
                    accountName = searchResultEntry.GetProp("name");
                    wrapper = new OU(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}"
                    };
                    break;
                case LdapTypeEnum.Domain:
                    wrapper = new Domain(searchResultEntry)
                    {
                        DisplayName = accountDomain
                    };
                    break;
                case LdapTypeEnum.Unknown:
                    wrapper = null;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            //Set the DN/SID for the wrapper going forward
            if (wrapper == null) return wrapper;
            wrapper.DistinguishedName = distinguishedName;
            wrapper.SecurityIdentifier = objectSid;

            //Return our wrapper for the next step in the pipeline
            return wrapper;
        }
    }
}
