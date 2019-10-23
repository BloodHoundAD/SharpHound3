using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound3.Tasks
{
    internal class LdapProducer
    {
        private readonly DirectorySearch _searcher;
        private readonly string _query;
        private readonly string[] _props;

        public LdapProducer(string domain, string query, string[] props)
        {
            _searcher = Helpers.GetDirectorySearcher(domain);
            _query = query;
            _props = props;
        }

        public async void ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            foreach (var searchResult in _searcher.QueryLdap(_query, _props, SearchScope.Subtree))
            {
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
