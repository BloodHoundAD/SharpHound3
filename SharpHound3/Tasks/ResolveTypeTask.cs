using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound3.Enums;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal static class ResolveTypeTask
    {
        internal static LdapWrapper FindLdapType(SearchResultEntry searchResultEntry)
        {
            //Look for a null DN first. Not sure why this would happen.
            var distinguishedName = searchResultEntry.DistinguishedName;
            if (distinguishedName == null)
                return null;

            var accountName = searchResultEntry.GetProperty("samaccountname");
            var samAccountType = searchResultEntry.GetProperty("samaccounttype");
            var accountDomain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var objectSid = searchResultEntry.GetSid();
            var objectType = LdapTypeEnum.Unknown;
            string objectIdentifier;

            LdapWrapper wrapper;

            //Lets see if its a "common" principal
            if (CommonPrincipal.GetCommonSid(objectSid, out var commonPrincipal))
            {
                accountName = commonPrincipal.Name;
                objectType = commonPrincipal.Type;
                objectIdentifier = Helpers.ConvertCommonSid(objectSid, accountDomain);
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
                    var objectClasses = searchResultEntry.GetPropertyAsArray("objectClass");
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
                objectIdentifier = searchResultEntry.GetObjectIdentifier();
            }

            //Depending on the object type, create the appropriate wrapper object
            switch (objectType)
            {
                case LdapTypeEnum.Computer:
                    accountName = accountName?.TrimEnd('$');
                    wrapper = new Computer(searchResultEntry)
                    {
                        DisplayName = $"{accountName}.{accountDomain}".ToUpper(),
                        SamAccountName = accountName
                    };
                    break;
                case LdapTypeEnum.User:
                    wrapper = new User(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    break;
                case LdapTypeEnum.Group:
                    wrapper = new Group(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    break;
                case LdapTypeEnum.GPO:
                    accountName = searchResultEntry.GetProperty("displayname");
                    wrapper = new GPO(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    break;
                case LdapTypeEnum.OU:
                    accountName = searchResultEntry.GetProperty("name");
                    wrapper = new OU(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    break;
                case LdapTypeEnum.Domain:
                    wrapper = new Domain(searchResultEntry)
                    {
                        DisplayName = accountDomain.ToUpper()
                    };
                    break;
                case LdapTypeEnum.Unknown:
                    wrapper = null;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            //Set the DN/SID for the wrapper going forward
            if (wrapper == null)
            {
                Console.WriteLine($"Null Wrapper: {distinguishedName}");
                return wrapper;
            }
            wrapper.DistinguishedName = distinguishedName;

            wrapper.ObjectIdentifier = objectIdentifier;

            //Return our wrapper for the next step in the pipeline
            return wrapper;
        }
    }
}
