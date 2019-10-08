using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace BHECollector.Tasks
{
    class LdapConsumer
    {
        internal static async Task Consume(IReceivableSourceBlock<SearchResultEntry> queue)
        {
            while (await queue.OutputAvailableAsync())
            {
                SearchResultEntry entry;
                while (queue.TryReceive(out entry))
                {

                }
            }
        }
    }
}
