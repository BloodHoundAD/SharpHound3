using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound3.Tasks;

namespace SharpHound3.Producers
{
    internal class ComputerFileProducer : BaseProducer
    {

        public ComputerFileProducer(string domainName, string query, string[] props) : base(domainName, query, props)
        {
        }

        protected override async Task ProduceLdap(ITargetBlock<SearchResultEntry> queue)
        {
            var computerFile = Options.Instance.ComputerFile;
            var token = Helpers.GetCancellationToken();
            OutputTasks.StartOutputTimer();
            using (var fileStream = new StreamReader(new FileStream(computerFile, FileMode.Open, FileAccess.Read)))
            {
                string computer;
                while ((computer = fileStream.ReadLine()) != null)
                {
                    if (token.IsCancellationRequested)
                    {
                        break;
                    }
                    string sid;
                    if (!computer.StartsWith("S-1-5-21"))
                    { 
                        //The computer isn't a SID so try to convert it to one
                        sid = await ResolutionHelpers.ResolveHostToSid(computer, DomainName);
                    }
                    else
                    {
                        //The computer is already a sid, so just store it off
                        sid = computer;
                    }

                    try
                    {
                        //Convert the sid to a hex representation and find the entry in the domain
                        var hexSid = Helpers.ConvertSidToHexSid(sid);
                        var entry = await Searcher.GetOne($"(objectsid={hexSid})", Props, SearchScope.Subtree);
                        if (entry == null)
                        {
                            //We couldn't find the entry for whatever reason
                            Console.WriteLine($"Failed to resolve {computer}");
                            continue;
                        }

                        //Success! Send the computer to be processed
                        await queue.SendAsync(entry);
                    }
                    catch
                    {
                        Console.WriteLine($"Failed to resolve {computer}");
                    }
                }
            }

            queue.Complete();
        }

        
    }
}
