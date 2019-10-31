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
            if (Options.Instance.ExcludeDomainControllers)
            {
                ConvertToWrapperTasks.SetDomainControllerSids(GetDomainControllerSids());
            }
        }

        internal Task StartProducer(ITargetBlock<SearchResultEntry> queue)
        {
            return Task.Run(async () => { await ProduceLdap(queue); });
        }

        protected HashSet<string> GetDomainControllerSids()
        {
            Console.WriteLine("[+] Pre-populating Domain Controller SIDS for ExcludeDomainControllers");
            var sids = Searcher
                .QueryLdap("(userAccountControl:1.2.840.113556.1.4.803:=8192)", new[] {"objectsid"},
                    SearchScope.Subtree).Select(entry => entry.GetSid()).Where(sid => sid != null).ToArray();
            var set = new HashSet<string>(sids);
            
            return set;
        }

        protected abstract Task ProduceLdap(ITargetBlock<SearchResultEntry> queue);
    }
}
