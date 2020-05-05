using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound3.Enums;
using SharpHound3.Tasks;

namespace SharpHound3.Producers
{
    internal class GentleLdapProducer : BaseProducer
    {
        private Queue<string> _targetQueue = new Queue<string>();
        private List<string> _seenTargets = new List<string>();
        public GentleLdapProducer(string domainName, string query, string[] props) : base(domainName, query, props)
        {
        }

        protected override async Task ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            var token = Helpers.GetCancellationToken();
            OutputTasks.StartOutputTimer();

            foreach (var searchResult in Searcher.QueryLdap(Query, Props, SearchScope.Base))
            {
                if (token.IsCancellationRequested)
                {
                    Console.WriteLine("[-] Terminating Producer as cancellation was requested. Waiting for pipeline to finish");
                    break;
                }

                await queue.SendAsync(searchResult);
            }

            foreach (var searchResult in Searcher.QueryLdap(Query, Props, SearchScope.OneLevel))
            {
                if (token.IsCancellationRequested)
                {
                    Console.WriteLine("[-] Terminating Producer as cancellation was requested. Waiting for pipeline to finish");
                    break;
                }

                await queue.SendAsync(searchResult);
                var type = searchResult.GetLdapType();
                
                if (type == LdapTypeEnum.Container || type == LdapTypeEnum.OU)
                {
                    _targetQueue.Enqueue(searchResult.DistinguishedName);
                }
            }

            while (_targetQueue.Count > 0)
            {
                var target = _targetQueue.Dequeue();
                _seenTargets.Add(target);
                await QueryLevel(target, queue);
            }

            queue.Complete();
        }

        private async Task QueryLevel(string distinguishedName, ITargetBlock<SearchResultEntry> queue)
        {
            var token = Helpers.GetCancellationToken();
            foreach (var searchResult in Searcher.QueryLdap(Query, Props, SearchScope.OneLevel, distinguishedName))
            {
                if (token.IsCancellationRequested)
                {
                    Console.WriteLine("[-] Terminating Producer as cancellation was requested. Waiting for pipeline to finish");
                    break;
                }
                await queue.SendAsync(searchResult);
                var type = searchResult.GetLdapType();
                if (type == LdapTypeEnum.Container || type == LdapTypeEnum.OU)
                {
                    var dn = searchResult.DistinguishedName;
                    if (!_seenTargets.Contains(dn))
                        _targetQueue.Enqueue(searchResult.DistinguishedName);
                }
            }
        }
    }
}
