using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;

namespace SharpHound3
{
    internal class DirectorySearch
    {
        private readonly string _domainController;
        private readonly string _domainName;
        private readonly Domain _domain;
        private Dictionary<string, string> _domainGuidMap;
        private readonly ConcurrentBag<LdapConnection> _connectionPool = new ConcurrentBag<LdapConnection>();

        public DirectorySearch(string domainName = null, string domainController = null)
        {
            _domainName = domainName;
            _domain = GetDomain();
            _domainName = _domain.Name;
            _domainController = Options.Instance.DomainController ?? domainController;
            CreateSchemaMap();
        }

        internal string[] LookupUserInGC(string username)
        {
            if (Cache.Instance.GetGlobalCatalogMatches(username, out var sids))
            {
                return sids;
            }

            var connection = GetGlobalCatalogConnection();
            try
            {
                var searchRequest = CreateSearchRequest($"(&(samAccountType=805306368)(samaccountname={username}))",
                    SearchScope.Subtree, new[] {"objectsid"});

                SearchResponse searchResponse;
                try
                {
                    searchResponse = (SearchResponse) connection.SendRequest(searchRequest);
                }
                catch (Exception e)
                {
                    Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}",
                        e.GetType().Name, e.Message);
                    return new string[0];
                }

                if (searchResponse.Entries.Count == 0)
                {
                    sids = new string[0];
                    Cache.Instance.Add(username, sids);
                    return sids;
                }
                    

                var results = new List<string>();

                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    var sid = entry.GetSid();
                    if (sid != null)
                        results.Add(sid);
                }

                sids = results.ToArray();
                Cache.Instance.Add(username, sids);
                return sids;
            }
            finally
            {
                connection.Dispose();
            }
        }

        internal SearchResultEntry GetOne(string ldapFilter, string[] props, SearchScope scope, string adsPath = null, bool globalCatalog = false)
        {
            var connection = globalCatalog ? GetGlobalCatalogConnection() : GetLdapConnection();
            try
            {
                var searchRequest = CreateSearchRequest(ldapFilter, scope, props);

                SearchResponse searchResponse;
                try
                {
                    searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                }
                catch (Exception e)
                {
                    Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}",
                        e.GetType().Name, e.Message);
                    return null;
                }

                if (searchResponse.Entries.Count == 0)
                    return null;

                return searchResponse.Entries[0];
            }
            finally
            {
                if (!globalCatalog)
                    _connectionPool.Add(connection);
            }
        }

        internal IEnumerable<SearchResultEntry> QueryLdap(string ldapFilter, string[] props, SearchScope scope, string adsPath = null, bool globalCatalog = false)
        {
            var connection = globalCatalog ? GetGlobalCatalogConnection() :  GetLdapConnection();
            try
            {
                var searchRequest = CreateSearchRequest(ldapFilter, scope, props);
                var pageRequest = new PageResultRequestControl(500);
                searchRequest.Controls.Add(pageRequest);

                if (Options.Instance.ResolvedCollectionMethods.HasFlag(CollectionMethodResolved.ACL))
                {
                    var securityDescriptorFlagControl = new SecurityDescriptorFlagControl
                    {
                        SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                    };
                    searchRequest.Controls.Add(securityDescriptorFlagControl);
                }

                while (true)
                {
                    SearchResponse searchResponse;
                    try
                    {
                        searchResponse = (SearchResponse) connection.SendRequest(searchRequest);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}",
                            e.GetType().Name, e.Message);
                        yield break;
                    }

                    if (searchResponse.Controls.Length != 1 ||
                        !(searchResponse.Controls[0] is PageResultResponseControl))
                    {
                        Console.WriteLine("Server does not support paging");
                        yield break;
                    }

                    var pageResponse = (PageResultResponseControl) searchResponse.Controls[0];

                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        yield return entry;
                    }

                    if (pageResponse.Cookie.Length == 0)
                        break;

                    pageRequest.Cookie = pageResponse.Cookie;
                }
            }
            finally
            {
                if (!globalCatalog)
                    _connectionPool.Add(connection);
            }
        }

        internal IEnumerable<string> RetrieveRangedAttribute(string distinguishedName, string attribute)
        {
            try
            {
                //Try ASQ first
                return RangeRetrievalAsq(distinguishedName, attribute);
            }
            catch
            {
                try
                {
                    return RangeRetrievalFallback(distinguishedName, attribute);
                }
                catch
                {
                    return null;
                }
            }
        }


        /// <summary>
        /// Attempt to retrieve an LDAP attribute from a DN using an Attribute Scoped Query
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="attribute"></param>
        /// <returns></returns>
        private IEnumerable<string> RangeRetrievalAsq(string distinguishedName, string attribute)
        {
            var connection = GetLdapConnection();
            try
            {
                var searchRequest = CreateSearchRequest("(objectclass=*)", SearchScope.Base, null, distinguishedName);
                var asq = new AsqRequestControl(attribute);
                searchRequest.Controls.Add(asq);

                var searchResponse = (SearchResponse) connection.SendRequest(searchRequest);

                if (searchResponse.Controls.Length != 1 || !(searchResponse.Controls[0] is AsqResponseControl))
                {
                    //The domain controller doesn't support ASQ for some reason. So fall back to old fashioned LDAP retrieval.
                    throw new ControlNotSupportedException();
                }

                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    yield return entry.DistinguishedName;
                }
            }
            finally
            {
                _connectionPool.Add(connection);
            }
        }

        /// <summary>
        /// Attempt to retrieve a ranged LDAP attribute using old school ranged retrieval
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="attribute"></param>
        /// <returns></returns>
        private IEnumerable<string> RangeRetrievalFallback(string distinguishedName, string attribute)
        {
            var connection = GetLdapConnection();
            try
            {
                var index = 0;
                var step = 0;
                var baseString = $"{attribute};";
                var currentRange = $"{baseString};range={index}-*";

                var searchRequest = CreateSearchRequest($"{attribute}=*", SearchScope.Base, new string[] {currentRange},
                    distinguishedName);

                var searchDone = false;

                while (true)
                {
                    var response = (SearchResponse) connection.SendRequest(searchRequest);

                    if (response?.Entries.Count == 1)
                    {
                        var entry = response.Entries[0];

                        foreach (string attr in entry.Attributes.AttributeNames)
                        {
                            currentRange = attr;
                            searchDone = currentRange.IndexOf("*", 0, StringComparison.Ordinal) > 0;
                            step = entry.Attributes[currentRange].Count;
                        }

                        foreach (string member in entry.Attributes[currentRange].GetValues(typeof(string)))
                        {
                            yield return member;
                            index++;
                        }

                        if (searchDone)
                        {
                            yield break;
                        }


                        currentRange = $"{baseString};range={index}-{index + step}";

                        searchRequest.Attributes.Clear();
                        searchRequest.Attributes.Add(currentRange);
                    }
                    else
                    {
                        yield break;
                    }
                }
            }
            finally
            {
                _connectionPool.Add(connection);
            }
        }

        internal bool GetNameFromGuid(string guid, out string name)
        {
            return _domainGuidMap.TryGetValue(guid, out name);
        }

        private Domain GetDomain()
        {
            try
            {
                if (_domainName == null)
                    return Domain.GetCurrentDomain();

                var context = new DirectoryContext(DirectoryContextType.Domain, _domainName);
                return Domain.GetDomain(context);
            }
            catch
            {
                return null;
            }
        }

        private DirectoryContext GetDomainContext()
        {
            return new DirectoryContext(DirectoryContextType.Domain, _domainName);
        }

        private LdapConnection GetGlobalCatalogConnection()
        {
            var domainController = _domainController ?? _domainName;
            var port = 3628;

            var identifier = new LdapDirectoryIdentifier(domainController, port, false, false);
            var connection = new LdapConnection(identifier);

            var ldapSessionOptions = connection.SessionOptions;
            if (!Options.Instance.DisableKerberosSigning)
            {
                ldapSessionOptions.Signing = true;
                ldapSessionOptions.Sealing = true;
            }

            ldapSessionOptions.ProtocolVersion = 3;
            ldapSessionOptions.ReferralChasing = ReferralChasingOptions.None;

            connection.Timeout = new TimeSpan(0, 5, 0);
            return connection;
        }

        private LdapConnection GetLdapConnection()
        {
            if (_connectionPool.TryTake(out var connection))
            {
                return connection;
            }

            var domainController = _domainController ?? _domainName;
            var port = Options.Instance.LdapPort == 0
                ? (Options.Instance.SecureLDAP ? 636 : 389)
                : Options.Instance.LdapPort;
            var identifier = new LdapDirectoryIdentifier(domainController, port, false, false);
            connection = new LdapConnection(identifier);

            var ldapSessionOptions = connection.SessionOptions;
            if (!Options.Instance.DisableKerberosSigning)
            {
                ldapSessionOptions.Signing = true;
                ldapSessionOptions.Sealing = true;
            }
            
            ldapSessionOptions.ProtocolVersion = 3;
            ldapSessionOptions.ReferralChasing = ReferralChasingOptions.None;
            
            connection.Timeout = new TimeSpan(0,5,0);
            return connection;
        }

        private SearchRequest CreateSearchRequest(string ldapFilter, SearchScope scope, string[] props, string adsPath=null)
        {
            var activeDirectorySearchPath = adsPath ?? $"DC={_domainName.Replace(".", ",DC=")}";
            var request = new SearchRequest(activeDirectorySearchPath, ldapFilter, scope, props);
            request.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));

            return request;
        }

        private void CreateSchemaMap()
        {
            var map = new Dictionary<string, string>();
            var path = _domain.Forest.Schema.Name;

            foreach (var result in QueryLdap("(schemaIDGUID=*)", new[] {"schemaidguid", "name"}, SearchScope.Subtree,
                path))
            {
                var name = result.GetProperty("name");
                var guid = new Guid(result.GetPropertyAsBytes("schemaidguid")).ToString();
                map.Add(guid, name);
            }

            _domainGuidMap = map;
        }

        ~DirectorySearch()
        {
            foreach (var connection in _connectionPool)
            {
                connection.Dispose();
            }
        }
    }
}
