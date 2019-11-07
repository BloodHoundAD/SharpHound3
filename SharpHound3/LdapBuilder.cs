using System.Collections.Generic;
using System.Linq;
using SharpHound3.Enums;

namespace SharpHound3
{
    internal class LdapBuilder
    {
        internal static LdapQueryData BuildLdapQuery(CollectionMethodResolved methods)
        {
            var ldapFilterParts = new List<string>();
            var ldapProperties = new List<string>();

            //We always want these properties to ensure we can at least pass type finding: "samaccounttype", "objectsid", "objectguid", "objectclass"
            ldapProperties.AddRange(Helpers.ResolutionProps);
            ldapProperties.Add("samaccountname");
            //LAPS is weird and several collection methods depend on it, but its easier to just have the property in all our collections
            ldapProperties.Add("ms-mcs-admpwdexpirationtime");
            
            //Group membership collection
            if (methods.HasFlag(CollectionMethodResolved.Group))
            {
                ldapFilterParts.Add("(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(primarygroupid=*))");
                ldapProperties.AddRange(new [] {"member", "primarygroupid"});
            }

            //Computer collection methods: ask for non-disabled computer objects
            if (methods.HasFlag(CollectionMethodResolved.LocalAdmin) ||
                methods.HasFlag(CollectionMethodResolved.Sessions) ||
                methods.HasFlag(CollectionMethodResolved.LoggedOn) || methods.HasFlag(CollectionMethodResolved.RDP) ||
                methods.HasFlag(CollectionMethodResolved.DCOM) || methods.HasFlag(CollectionMethodResolved.PSRemote))
            {
                ldapFilterParts.Add("(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))");
            }

            if (methods.HasFlag(CollectionMethodResolved.ACL))
            {
                ldapFilterParts.Add("(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*))(objectcategory=organizationalUnit))");
                ldapProperties.AddRange(new []
                {
                    "ntsecuritydescriptor", "displayname", "name"
                });
            }

            if (methods.HasFlag(CollectionMethodResolved.Trusts))
            {
                ldapFilterParts.Add("(objectclass=domain)");
            }

            if (methods.HasFlag(CollectionMethodResolved.ObjectProps))
            {
                ldapFilterParts.Add("(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(samaccounttype=805306368)(samaccounttype=805306369)(objectclass=domain)(objectclass=organizationalUnit)(&(objectcategory=groupPolicyContainer)(flags=*)))");
                ldapProperties.AddRange(new[]
                {
                    "pwdlastset", "lastlogon", "lastlogontimestamp", "objectsid",
                    "sidhistory", "useraccountcontrol", "operatingsystem",
                    "operatingsystemservicepack", "serviceprincipalname", "displayname", "mail", "title",
                    "homedirectory","description","admincount","userpassword","gpcfilesyspath","objectclass",
                    "msds-behavior-version","objectguid", "name", "gpoptions", "msds-allowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "displayname"
                });
            }

            if (methods.HasFlag(CollectionMethodResolved.Container))
            {
                ldapFilterParts.Add("(|(&(&(objectcategory=groupPolicyContainer)(flags=*))(name=*)(gpcfilesyspath=*))(objectcategory=organizationalUnit)(objectClass=domain))");
                ldapProperties.AddRange(new[] {"gplink", "gpoptions", "name", "displayname"});
            }

            if (methods.HasFlag(CollectionMethodResolved.GPOLocalGroup))
            {
                //ldapFilterParts.Add("(&(&(objectcategory=groupPolicyContainer)(flags=*))(name=*)(gpcfilesyspath=*))");
                //ldapProperties.AddRange(new[] {"gpcfilesyspath", "displayname"});
                ldapFilterParts.Add("(&(|(objectcategory=organizationalUnit)(objectclass=domain))(gplink=*))");
                ldapProperties.AddRange(new []{"gplink", "name" });
            }

            if (methods.HasFlag(CollectionMethodResolved.SPNTargets))
            {
                ldapFilterParts.Add("(&(samaccounttype=805306368)(serviceprincipalname=*))");
                ldapProperties.AddRange(new[]
                {
                    "serviceprincipalname"
                });
            }

            var finalFilter = string.Join("", ldapFilterParts.ToArray());
            finalFilter = ldapFilterParts.Count == 1 ? ldapFilterParts[0] : $"(|{finalFilter})";

            var userFilter = Options.Instance.LdapFilter;
            if (userFilter != null)
            {
                finalFilter = $"(&({finalFilter})({userFilter}))";
            }

            if (Options.Instance.WindowsOnly)
            {
                finalFilter = $"(&({finalFilter})(operatingsystem=*windows*))";
            }

            return new LdapQueryData
            {
                LdapFilter = finalFilter,
                LdapProperties = ldapProperties.Distinct().ToArray()
            };
        }
    }

    internal class LdapQueryData
    {
        public string LdapFilter { get; set; }
        public string[] LdapProperties { get; set; }
    }
}
