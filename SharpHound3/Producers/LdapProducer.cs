using System;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound3.Tasks;

namespace SharpHound3.Producers
{
    internal class LdapProducer : BaseProducer
    {
        public LdapProducer(string domainName, string query, string[] props) : base(domainName, query, props)
        {
        }

        /// <summary>
        /// Uses the LDAP filter and properties specified to grab data from LDAP, and push it to the queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected override async Task ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            var token = Helpers.GetCancellationToken();
            OutputTasks.StartOutputTimer();
            //Do a basic  LDAP search and grab results
            foreach (var searchResult in Searcher.QueryLdap(Query, Props, SearchScope.Subtree,Options.Instance.SearchBase))
            {
                //If our cancellation token is set, cancel out of our loop
                if (token.IsCancellationRequested)
                {
                    Console.WriteLine("[-] Terminating Producer as cancellation was requested. Waiting for pipeline to finish");
                    break;
                }
                await queue.SendAsync(searchResult);
            }
            queue.Complete();
        }
    }
}
