using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using CommandLine;
using SharpHound3.LdapWrappers;
using SharpHound3.Tasks;

namespace SharpHound3
{
    class SharpHound
    {
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args).WithParsed(o => { Options.Instance = o; });
            var producer = new LdapProducer(null, "(objectclass=*)", new string[0]);
            var linkOptions = new DataflowLinkOptions
            {
                PropagateCompletion = true
            };

            var findTypeBlock = new TransformBlock<SearchResultEntry, LdapWrapper>(ResolveTypeTask.FindLdapType, new ExecutionDataflowBlockOptions
            {
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 250
            });

            var processGroupBlock = new TransformBlock<LdapWrapper, LdapWrapper>(GroupEnumerationTasks.ProcessGroupMembership, new ExecutionDataflowBlockOptions
            {
                BoundedCapacity = 250
            });

            var outputBlock = new ActionBlock<LdapWrapper>(OutputTasks.WriteJsonOutput, new ExecutionDataflowBlockOptions
            {
                BoundedCapacity = 250,
                MaxDegreeOfParallelism = 1
            });

            findTypeBlock.LinkTo(processGroupBlock, linkOptions, wrapper => wrapper != null);
            findTypeBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>(), (item) => (item == null));
            processGroupBlock.LinkTo(outputBlock, linkOptions);
            producer.StartProducer(findTypeBlock);
            outputBlock.Completion.Wait();

            OutputTasks.CompleteOutput();

            //var processDaclBlock = new TransformBlock<LdapWrapper, LdapWrapper>(ACLTasks.ProcessDACL, new ExecutionDataflowBlockOptions
            //{
            //    MaxDegreeOfParallelism = 10,
            //    BoundedCapacity = 250
            //});

            //var processPropertiesBlock = new TransformBlock<LdapWrapper, LdapWrapper>(ObjectPropertyTasks.ResolveObjectProperties, new ExecutionDataflowBlockOptions
            //{
            //    MaxDegreeOfParallelism = 5,
            //    BoundedCapacity = 250
            //});

            //var processContainerBlock = new TransformBlock<LdapWrapper, LdapWrapper>(ContainerTasks.EnumerateContainer, new ExecutionDataflowBlockOptions
            //{
            //    MaxDegreeOfParallelism = 5,
            //    BoundedCapacity = 250
            //});

            //findTypeBlock.LinkTo(processDaclBlock, linkOptions, wrapper => wrapper != null);
            //findTypeBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>(), (item) => (item == null));
            //processDaclBlock.LinkTo(processPropertiesBlock, linkOptions);
            //processPropertiesBlock.LinkTo(processContainerBlock, linkOptions);
            //processContainerBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>());
            //producer.StartProducer(findTypeBlock);
            //processPropertiesBlock.Completion.Wait();
        }
    }
}
