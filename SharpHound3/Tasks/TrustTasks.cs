using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;
using SharpHound3.Producers;

namespace SharpHound3.Tasks
{
    internal class TrustTasks
    {
        private static readonly string[] LookupProps = {"trustattributes", "securityidentifier", "trustdirection", "trusttype", "cn"};

        internal static LdapWrapper ResolveDomainTrusts(LdapWrapper wrapper)
        {
            if (wrapper is Domain domain)
            {
                DoTrustEnumeration(domain);
            }
            
            return wrapper;
        }

        private static void DoTrustEnumeration(Domain domain)
        {
            var searcher = Helpers.GetDirectorySearcher(domain.Domain);
            var trusts = searcher.QueryLdap("(objectclass=trusteddomain)", LookupProps, SearchScope.Subtree).Select(
                trustedDomain =>
                {
                    var trustDirection = (TrustDirection)int.Parse(trustedDomain.GetProperty("trustdirection"));
                    var trustAttributes = (TrustAttributes)int.Parse(trustedDomain.GetProperty("trustattributes"));
                    var targetSid = new SecurityIdentifier(trustedDomain.GetPropertyAsBytes("securityidentifier"), 0).Value;
                    var transitive = (trustAttributes & TrustAttributes.NonTransitive) == 0;
                    var targetName = trustedDomain.GetProperty("cn").ToUpper();

                    TrustType trustType;

                    if ((trustAttributes & TrustAttributes.WithinForest) != 0)
                    {
                        trustType = TrustType.ParentChild;
                    }else if ((trustAttributes & TrustAttributes.ForestTransitive) != 0)
                    {
                        trustType = TrustType.Forest;
                    }else if ((trustAttributes & TrustAttributes.TreatAsExternal) != 0 ||
                              (trustAttributes & TrustAttributes.CrossOrganization) != 0)
                    {
                        trustType = TrustType.External;
                    }
                    else
                    {
                        trustType = TrustType.Unknown;
                    }

                    return new Trust
                    {
                        IsTransitive = transitive,
                        TrustDirection = trustDirection,
                        TargetDomainSid = targetSid,
                        TrustType = trustType,
                        TargetDomainName = targetName
                    };
                }).ToArray();
            domain.Trusts = trusts;
        }

        [Flags]
        private enum TrustAttributes
        {
            NonTransitive = 0x1,
            UplevelOnly = 0x2,
            FilterSids = 0x4,
            ForestTransitive = 0x8,
            CrossOrganization = 0x10,
            WithinForest = 0x20,
            TreatAsExternal = 0x40,
            TrustUsesRc4 = 0x80,
            TrustUsesAes = 0x100,
            CrossOrganizationNoTGTDelegation = 0x200,
            PIMTrust = 0x400
        }
    }
}
