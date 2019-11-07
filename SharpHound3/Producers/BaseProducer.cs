using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound3.Tasks;

namespace SharpHound3.Producers
{
    internal abstract class BaseProducer
    {
        protected static Dictionary<string, SearchResultEntry> _domainControllerSids;
        protected readonly DirectorySearch Searcher;
        protected readonly string Query;
        protected readonly string[] Props;
        protected readonly string DomainName;

        protected BaseProducer(string domainName, string query, string[] props)
        {
            Searcher = Helpers.GetDirectorySearcher(domainName);
            Query = query;
            Props = props;
            DomainName = domainName;
            SetDomainControllerSids(GetDomainControllerSids());
        }

        private static void SetDomainControllerSids(Dictionary<string, SearchResultEntry> dcs)
        {
            if (_domainControllerSids == null)
            {
                _domainControllerSids = dcs;
            }
            else
            {
                foreach (var target in dcs)
                {
                    _domainControllerSids.Add(target.Key, target.Value);
                }
            }
        }

        internal static bool IsSidDomainController(string sid)
        {
            return _domainControllerSids.ContainsKey(sid);
        }

        internal static Dictionary<string, SearchResultEntry> GetDCSids()
        {
            return _domainControllerSids;
        }

        internal Task StartProducer(ITargetBlock<SearchResultEntry> queue)
        {
            return Task.Run(async () => { await ProduceLdap(queue); });
        }

        protected Dictionary<string, SearchResultEntry> GetDomainControllerSids()
        {
            Console.WriteLine("[+] Pre-populating Domain Controller SIDS");
            var temp = new Dictionary<string, SearchResultEntry>();
            foreach (var entry in Searcher
                .QueryLdap("(userAccountControl:1.2.840.113556.1.4.803:=8192)", new[] {"objectsid"},
                    SearchScope.Subtree))
            {
                var sid = entry.GetSid();
                if (sid != null)
                    temp.Add(sid, entry);
            }

            return temp;
        }

        protected abstract Task ProduceLdap(ITargetBlock<SearchResultEntry> queue);
    }
}
