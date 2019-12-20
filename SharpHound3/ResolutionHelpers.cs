using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.Enums;

namespace SharpHound3
{
    internal class ResolutionHelpers
    {
        private static readonly ConcurrentDictionary<string, string> SidToDomainNameCache = new ConcurrentDictionary<string, string>();

        internal async Task<(string finalSid, LdapTypeEnum type)> ResolveSidAndGetType(string sid, string domain)
        {
            if (sid.Contains("0ACNF"))
                return (null, LdapTypeEnum.Unknown);

            if (CommonPrincipal.GetCommonSid(sid, out var commonPrincipal))
            {
                var newSid = Helpers.ConvertCommonSid(sid, domain);
                return (newSid, commonPrincipal.Type);
            }

            if (Cache.Instance.GetSidType(sid, out var type))
                return (sid, type);

            type = await LookupSidType(sid);
            return (sid, type);
        }

        private static async Task<LdapTypeEnum> LookupSidType(string sid)
        {
            var hexSid = ConvertSidToHexSid(sid);
            if (hexSid == null)
                return LdapTypeEnum.Unknown;

            var domain = await GetDomainNameFromSid(sid);
            var searcher = Helpers.GetDirectorySearcher(domain);

            var result = await searcher.GetOne($"(objectsid={hexSid})", Helpers.ResolutionProps, SearchScope.Subtree);

            return result?.GetLdapType() ?? LdapTypeEnum.Unknown;
        }

        private static string ConvertSidToHexSid(string sid)
        {
            try
            {
                var securityIdentifier = new SecurityIdentifier(sid);
                var sidBytes = new byte[securityIdentifier.BinaryLength];
                securityIdentifier.GetBinaryForm(sidBytes,0);
                var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
                return output;
            }
            catch
            {
                return null;
            }
        }

        private static async Task<string> GetDomainNameFromSid(string sid)
        {
            try
            {
                var securityIdentifier = new SecurityIdentifier(sid);

                var domainSid = securityIdentifier.AccountDomainSid?.Value.ToUpper();

                if (domainSid == null)
                    return null;

                if (SidToDomainNameCache.TryGetValue(domainSid, out var domainName))
                    return domainName;

                var domain = await GetDomainNameFromSidLdap(sid);

                SidToDomainNameCache.TryAdd(sid, domain);
                return domain;
            }
            catch
            {
                return null;
            }
        }

        private static async Task<string> GetDomainNameFromSidLdap(string sid)
        {
            var searcher = Helpers.GetDirectorySearcher(Options.Instance.Domain);
            var hexSid = ConvertSidToHexSid(sid);

            if (hexSid == null)
                return null;

            //Search using objectsid first
            var result = await searcher.GetOne($"(&(objectclass=domain)(objectsid={hexSid}))", new[] { "distinguishedname" }, SearchScope.Subtree, globalCatalog: true);

            if (result != null)
            {
                var domainName = Helpers.DistinguishedNameToDomain(result.DistinguishedName);
                return domainName;
            }

            //Try trusteddomain objects with the securityidentifier attribute
            result = await searcher.GetOne($"(&(objectclass=trusteddomain)(securityidentifier={sid}))",
                new[] { "cn" }, SearchScope.Subtree, globalCatalog: true);

            if (result != null)
            {
                var domainName = result.GetProperty("cn");
                return domainName;
            }

            //We didn't find anything so just return null
            return null;
        }
    }
}
