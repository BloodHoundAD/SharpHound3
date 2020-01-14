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
        private static Dictionary<string, SearchResultEntry> _stealthTargetSids;
        private bool _stealthTargetsBuilt;

        public StealthProducer(string domainName, string query, string[] props) : base(domainName, query, props)
        {
        }

        private static void SetStealthTargetSids(Dictionary<string, SearchResultEntry> targets)
        {
            if (_stealthTargetSids == null)
                _stealthTargetSids = targets;
            else
            {
                foreach (var target in targets)
                {
                    _stealthTargetSids.Add(target.Key, target.Value);
                }
            }
        }

        internal static bool IsSidStealthTarget(string sid)
        {
            return _stealthTargetSids.ContainsKey(sid);
        }

        protected override async Task ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            var token = Helpers.GetCancellationToken();
            if (!_stealthTargetsBuilt)
            {
                Console.WriteLine("[+] Finding Stealth Targets from LDAP Properties");
                Console.WriteLine();
                var targetSids = await FindPathTargetSids();
                SetStealthTargetSids(targetSids);
                _stealthTargetsBuilt = true;

                OutputTasks.StartOutputTimer();
                foreach (var searchResult in Searcher.QueryLdap(Query, Props, SearchScope.Subtree))
                {
                    if (token.IsCancellationRequested)
                    {
                        Console.WriteLine("[-] Terminating Producer as cancellation was requested. Waiting for pipeline to finish");
                        break;
                    }
                        
                    await queue.SendAsync(searchResult);
                }
                queue.Complete();
            }
            else
            {
                OutputTasks.StartOutputTimer();
                var targets = new List<SearchResultEntry>();
                targets.AddRange(_stealthTargetSids.Values);
                if (!Options.Instance.ExcludeDomainControllers)
                    targets.AddRange(DomainControllerSids.Values);

                foreach (var searchResult in targets)
                {
                    if (token.IsCancellationRequested)
                        break;
                    await queue.SendAsync(searchResult);
                }
                queue.Complete();
            }
        }

        private async Task<Dictionary<string, SearchResultEntry>> FindPathTargetSids()
        {
            var paths = new ConcurrentDictionary<string, byte>();
            var sids = new Dictionary<string, SearchResultEntry>();
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
                var sid = await ResolutionHelpers.ResolveHostToSid(path, DomainName);
                if (sid != null)
                {
                    var searchResult = await Searcher.GetOne($"(objectsid={Helpers.ConvertSidToHexSid(sid)})", Props,
                        SearchScope.Subtree);
                    sids.Add(sid, searchResult);
                }
            }

            return sids;
        }
    }
}
