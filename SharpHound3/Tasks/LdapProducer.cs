using System.DirectoryServices.Protocols;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound3.Tasks
{
    internal class LdapProducer
    {
        private readonly DirectorySearch _searcher;
        private readonly string _query;
        private readonly string[] _props;
        private readonly CancellationToken _cancellationToken;

        public LdapProducer(string domain, string query, string[] props, CancellationToken cancellationToken)
        {
            _searcher = Helpers.GetDirectorySearcher(domain);
            _query = query;
            _props = props;
            _cancellationToken = cancellationToken;
        }

        public async void ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            foreach (var searchResult in _searcher.QueryLdap(_query, _props, SearchScope.Subtree))
            {
                if (_cancellationToken.IsCancellationRequested)
                    break;
                await queue.SendAsync(searchResult);
            }
            queue.Complete();
        }

        public Task StartProducer(ITargetBlock<SearchResultEntry> queue)
        {
            return Task.Factory.StartNew(() => ProduceLdap(queue), TaskCreationOptions.LongRunning);
        }

    }
}
