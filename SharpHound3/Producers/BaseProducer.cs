using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound3.Producers
{
    /// <summary>
    /// Base class for producing LDAP data to feed to other parts of the program
    /// </summary>
    internal abstract class BaseProducer
    {
        protected static Dictionary<string, SearchResultEntry> DomainControllerSids;
        protected readonly DirectorySearch Searcher;
        protected readonly string Query;
        protected readonly string[] Props;
        protected readonly string DomainName;

        protected BaseProducer(string domainName, string query, string[] props)
        {
            //Create a Directory Searcher using the domain specified
            Searcher = Helpers.GetDirectorySearcher(domainName);
            Query = query;
            Props = props;
            DomainName = domainName;
            SetDomainControllerSids(GetDomainControllerSids());
        }

        /// <summary>
        /// Sets the dictionary of Domain Controller sids, and merges in new ones
        /// </summary>
        /// <param name="dcs"></param>
        private static void SetDomainControllerSids(Dictionary<string, SearchResultEntry> dcs)
        {
            if (DomainControllerSids == null)
            {
                DomainControllerSids = dcs;
            }
            else
            {
                foreach (var target in dcs)
                {
                    try
                    {
                        DomainControllerSids.Add(target.Key, target.Value);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Checks if a SID is in the domain controllers list
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        internal static bool IsSidDomainController(string sid)
        {
            return DomainControllerSids.ContainsKey(sid);
        }

        /// <summary>
        /// Gets the dictionary of Domain Controller sids
        /// </summary>
        /// <returns></returns>
        internal static Dictionary<string, SearchResultEntry> GetDomainControllers()
        {
            return DomainControllerSids;
        }

        /// <summary>
        /// Starts the producer. 
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        internal Task StartProducer(ITargetBlock<SearchResultEntry> queue)
        {
            return Task.Run(async () => { await ProduceLdap(queue); });
        }

        /// <summary>
        /// Populates the list of domain controller SIDs using LDAP
        /// </summary>
        /// <returns></returns>
        protected Dictionary<string, SearchResultEntry> GetDomainControllerSids()
        {
            Console.WriteLine("[+] Pre-populating Domain Controller SIDS");
            var temp = new Dictionary<string, SearchResultEntry>();
            foreach (var entry in Searcher
                .QueryLdap("(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", new[] { "objectsid", "samaccountname" },
                    SearchScope.Subtree))
            {
                var sid = entry.GetSid();
                if (sid != null)
                    temp.Add(sid, entry);
            }

            return temp;
        }

        /// <summary>
        /// Produces SearchResultEntry items from LDAP and pushes them to a queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected abstract Task ProduceLdap(ITargetBlock<SearchResultEntry> queue);
    }
}
