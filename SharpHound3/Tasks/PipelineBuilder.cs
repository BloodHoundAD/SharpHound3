using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound3.Enums;
using SharpHound3.LdapWrappers;
using SharpHound3.Producers;

namespace SharpHound3.Tasks
{
    /// <summary>
    /// Creates the enumeration pipeline
    /// </summary>
    internal class PipelineBuilder
    {
        internal static Task GetBasePipelineForDomain(string domain)
        {
            var options = Options.Instance;
            var resolvedMethods = options.ResolvedCollectionMethods;
            var ldapVariables = LdapBuilder.BuildLdapQuery(resolvedMethods);
            BaseProducer producer;
            if (options.Stealth)
            {
                producer = new StealthProducer(domain, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }
            else if (options.ComputerFile != null)
            {
                producer = new ComputerFileProducer(domain, null, ldapVariables.LdapProperties);
            }
            else
            {
                producer = new LdapProducer(domain, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }

            var linkOptions = new DataflowLinkOptions
            {
                PropagateCompletion = true
            };

            var executionOptions = new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            };

            //Store our blocks in a list for linking
            var blocks = new List<TransformBlock<LdapWrapper, LdapWrapper>>();

            //The first block will always convert searchresults to the wrapper object
            var findTypeBlock = new TransformBlock<SearchResultEntry, LdapWrapper>(ConvertToWrapperTasks.CreateLdapWrapper, new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            });

            //Link null wrappers to a nulltarget block. We don't do anything with them
            findTypeBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>(), item => item == null);

            //Keep this variable to make instantiation easy
            TransformBlock<LdapWrapper, LdapWrapper> block = null;

            //Start with pure LDAP collection methods
            if ((resolvedMethods & CollectionMethodResolved.ACL) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ACLTasks.ProcessAces, executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.Group) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(GroupEnumerationTasks.ProcessGroupMembership,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.ObjectProps) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ObjectPropertyTasks.ResolveObjectProperties,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.Container) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ContainerTasks.EnumerateContainer,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.GPOLocalGroup) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(GPOGroupTasks.ParseGPOLocalGroups,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.SPNTargets) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(SPNTasks.ProcessSPNS, executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.Trusts) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(TrustTasks.ResolveDomainTrusts, executionOptions);
                blocks.Add(block);
            }

            //Start computer block

            //Only add this block if there's actually computer collection happening 
            if (options.IsComputerCollectionSet())
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ComputerAvailableTasks.CheckSMBOpen,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.Sessions) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(NetSessionTasks.ProcessNetSessions,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.RDP) != 0 || (resolvedMethods & CollectionMethodResolved.DCOM) != 0 ||
                (resolvedMethods & CollectionMethodResolved.LocalAdmin) != 0 ||
                (resolvedMethods & CollectionMethodResolved.PSRemote) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LocalGroupTasks.GetLocalGroupMembers,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.LoggedOn) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LoggedOnTasks.ProcessLoggedOn, executionOptions);
                blocks.Add(block);
            }

            if (blocks.Count == 0)
            {
                findTypeBlock.Complete();
                return findTypeBlock.Completion;
            }

            var linked = false;
            foreach (var toLink in blocks)
            {
                if (!linked)
                {
                    findTypeBlock.LinkTo(toLink, linkOptions, item => item != null);
                    linked = true;
                }
                else
                {
                    block.LinkTo(toLink, linkOptions, item => item != null);
                }
                block = toLink;
            }

            ITargetBlock<LdapWrapper> outputBlock;
            if (options.NoOutput)
            {
                outputBlock = new ActionBlock<LdapWrapper>(wrapper =>
                {
                    //Do nothing
                }, executionOptions);
            }
            else
            {
                //The output block should only have a single thread for writing to prevent issues
                outputBlock = new ActionBlock<LdapWrapper>(OutputTasks.WriteJsonOutput, new ExecutionDataflowBlockOptions
                {
                    BoundedCapacity = 500,
                    MaxDegreeOfParallelism = 1,
                    EnsureOrdered = false
                });
            }

            block.LinkTo(outputBlock, linkOptions);
            producer.StartProducer(findTypeBlock);
            return outputBlock.Completion;
        }

        internal static Task GetLoopPipelineForDomain(string domain)
        {
            var options = Options.Instance;
            var resolvedMethods = options.GetLoopCollectionMethods();
            Helpers.StartNewRun();
            var ldapVariables = LdapBuilder.BuildLdapQuery(resolvedMethods);
            BaseProducer producer;
            if (Options.Instance.Stealth)
            {
                producer = new StealthProducer(domain, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }
            else
            {
                producer = new LdapProducer(domain, ldapVariables.LdapFilter, ldapVariables.LdapProperties);
            }

            var linkOptions = new DataflowLinkOptions
            {
                PropagateCompletion = true
            };

            var executionOptions = new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            };

            //Store our blocks in a list for linking
            var blocks = new List<TransformBlock<LdapWrapper, LdapWrapper>>();

            var findTypeBlock = new TransformBlock<SearchResultEntry, LdapWrapper>(ConvertToWrapperTasks.CreateLdapWrapper, new ExecutionDataflowBlockOptions
            {
                EnsureOrdered = false,
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 500
            });

            findTypeBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>(), item => item == null);

            //Keep this variable to make instantiation easy
            TransformBlock<LdapWrapper, LdapWrapper> block = null;


            if (!options.SkipPortScan && options.IsComputerCollectionSet())
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(ComputerAvailableTasks.CheckSMBOpen,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.Sessions) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(NetSessionTasks.ProcessNetSessions,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.RDP) != 0 || (resolvedMethods & CollectionMethodResolved.DCOM) != 0 ||
                (resolvedMethods & CollectionMethodResolved.LocalAdmin) != 0 ||
                (resolvedMethods & CollectionMethodResolved.PSRemote) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LocalGroupTasks.GetLocalGroupMembers,
                    executionOptions);
                blocks.Add(block);
            }

            if ((resolvedMethods & CollectionMethodResolved.LoggedOn) != 0)
            {
                block = new TransformBlock<LdapWrapper, LdapWrapper>(LoggedOnTasks.ProcessLoggedOn, executionOptions);
                blocks.Add(block);
            }

            if (blocks.Count == 0)
            {
                findTypeBlock.Complete();
                return findTypeBlock.Completion;
            }

            var linked = false;
            foreach (var toLink in blocks)
            {
                if (!linked)
                {
                    findTypeBlock.LinkTo(toLink, linkOptions, item => item != null);
                    linked = true;
                }
                else
                {
                    block.LinkTo(toLink, linkOptions, item => item != null);
                }
                block = toLink;
            }

            ITargetBlock<LdapWrapper> outputBlock;
            if (options.NoOutput)
            {
                outputBlock = new ActionBlock<LdapWrapper>(wrapper =>
                {
                    //Do nothing
                }, executionOptions);
            }
            else
            {
                //The output block should only have a single thread for writing to prevent issues
                outputBlock = new ActionBlock<LdapWrapper>(OutputTasks.WriteJsonOutput, new ExecutionDataflowBlockOptions
                {
                    BoundedCapacity = 500,
                    MaxDegreeOfParallelism = 1,
                    EnsureOrdered = false
                });
            }

            block.LinkTo(outputBlock, linkOptions);
            producer.StartProducer(findTypeBlock);
            return outputBlock.Completion;
        }

    }
}
