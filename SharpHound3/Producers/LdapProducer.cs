using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound3.Producers
{
    internal class LdapProducer : BaseProducer
    {
        public LdapProducer(string domainName, string query, string[] props) : base(domainName, query, props)
        {
        }

        protected override async Task ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            var token = Helpers.GetCancellationToken();
            foreach (var searchResult in Searcher.QueryLdap(Query, Props, SearchScope.Subtree))
            {
                if (token.IsCancellationRequested)
                    break;
                await queue.SendAsync(searchResult, token);
            }
            queue.Complete();
        }
    }
}
