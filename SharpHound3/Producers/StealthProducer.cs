using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound3.Tasks;

namespace SharpHound3.Producers
{
    internal class StealthProducer : BaseProducer
    {
        public StealthProducer(string domainName, string query, string[] props) : base(domainName, query, props)
        {
        }

        protected override async Task ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            Console.WriteLine("[+] Finding Stealth Targets from LDAP Properties");
            Console.WriteLine();
            var targetSids = await FindPathTargetSids();
            ConvertToWrapperTasks.SetStealthTargetSids(targetSids);
            var token = Helpers.GetCancellationToken();
            OutputTasks.StartOutputTimer();
            foreach (var searchResult in Searcher.QueryLdap(Query, Props, SearchScope.Subtree))
            {
                if (token.IsCancellationRequested)
                    break;
                await queue.SendAsync(searchResult, token);
            }
            queue.Complete();
        }

        private async Task<HashSet<string>> FindPathTargetSids()
        {
            var paths = new ConcurrentDictionary<string, byte>();
            var sids = new HashSet<string>();
            Parallel.ForEach(Searcher.QueryLdap(
                "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))",
                new[] {"homedirectory", "scriptpath", "profilepath"}, SearchScope.Subtree), (searchResult) =>
            {
                
                var poss = new[]
                {
                    searchResult.GetProperty("homedirectory"), searchResult.GetProperty("scriptpath"),
                    searchResult.GetProperty("profilepath")
                };

                foreach (var s in poss)
                {
                    var split = s?.Split('\\');
                    if (!(split?.Length >= 3)) continue;
                    var path = split[2];
                    paths.TryAdd(path, new byte());
                }
            });


            foreach (var path in paths.Keys)
            {
                var sid = await Helpers.TryResolveHostToSid(path, DomainName);
                if (sid != null)
                {
                    sids.Add(sid);
                }
            }

            return sids;
        }
    }
}
