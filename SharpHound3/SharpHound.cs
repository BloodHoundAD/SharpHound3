using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using CommandLine;
using Heijden.DNS;
using SharpHound3.Enums;
using SharpHound3.LdapWrappers;
using SharpHound3.Tasks;

namespace SharpHound3
{
    class SharpHound
    {
        static void Main(string[] args)
        {

            //TODO: GPOLocalGroup, Trusts
            var parser = new Parser(with =>
            {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false;
                with.HelpWriter = Console.Error;
            });

            parser.ParseArguments<Options>(args).WithParsed(o =>
            {
                if (o.OverrideUserName != null)
                {
                    o.CurrentUserName = o.OverrideUserName;
                }
                else
                {
                    o.CurrentUserName = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
                }

                Options.Instance = o;
                Cache.CreateInstance();
            }).WithNotParsed(error => {

            });

            parser.Dispose();

            if (Options.Instance == null)
                return;

            if (!Options.Instance.ResolveCollectionMethods())
            {
                return;
            }

            TransformBlock<LdapWrapper,LdapWrapper> lastBlock = null;

            //We always need the producer
            var ldapVars = LdapBuilder.BuildLdapQuery();
            var producer = new LdapProducer(null, ldapVars.LdapFilter, ldapVars.LdapProperties);
            Task compErrorTask = null;
            if (Options.Instance.DumpComputerStatus)
            {
                compErrorTask = OutputTasks.StartComputerStatusTask();
            }

            var linkOptions = new DataflowLinkOptions
            {
                PropagateCompletion = true
            };
            var firstLinked = false;

            //FindType is always the first block
            var findTypeBlock = new TransformBlock<SearchResultEntry, LdapWrapper>(ResolveTypeTask.FindLdapType, new ExecutionDataflowBlockOptions
            {
                MaxDegreeOfParallelism = 10,
                BoundedCapacity = 250,
                EnsureOrdered = false
            });

            findTypeBlock.LinkTo(DataflowBlock.NullTarget<LdapWrapper>(), (item) => item == null);

            var resolved = Options.Instance.ResolvedCollectionMethods;

            Console.WriteLine($"Resolved Collection Methods: {resolved}");

            if ((resolved & CollectionMethodResolved.GPOLocalGroup) != 0)
            {
                Console.WriteLine("Building Cache for GPOLocalGroup");
                GPOGroupTasks.BuildOuGplinkCache(Options.Instance.Domain);
            }

            if ((resolved & CollectionMethodResolved.ACL) != 0)
            {
                var processDaclBlock = new TransformBlock<LdapWrapper, LdapWrapper>(ACLTasks.ProcessDACL, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 10,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });
                findTypeBlock.LinkTo(processDaclBlock, linkOptions, (item) => item != null);
                firstLinked = true;

                lastBlock = processDaclBlock;
            }

            if ((resolved & CollectionMethodResolved.Group) != 0)
            {
                var processGroupBlock = new TransformBlock<LdapWrapper, LdapWrapper>(GroupEnumerationTasks.ProcessGroupMembership, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 20,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(processGroupBlock, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(processGroupBlock, linkOptions);
                }

                lastBlock = processGroupBlock;
            }

            if ((resolved & CollectionMethodResolved.ObjectProps) != 0)
            {
                var processPropertiesBlock = new TransformBlock<LdapWrapper, LdapWrapper>(ObjectPropertyTasks.ResolveObjectProperties, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 10,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(processPropertiesBlock, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(processPropertiesBlock, linkOptions);
                }

                lastBlock = processPropertiesBlock;
            }

            if ((resolved & CollectionMethodResolved.Trusts) != 0)
            {

            }

            if ((resolved & CollectionMethodResolved.Container) != 0)
            {
                var processContainerBlock = new TransformBlock<LdapWrapper, LdapWrapper>(ContainerTasks.EnumerateContainer, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 10,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(processContainerBlock, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(processContainerBlock, linkOptions);
                }

                lastBlock = processContainerBlock;
            }

            if ((resolved & CollectionMethodResolved.GPOLocalGroup) != 0)
            {
                var processGpoLocalGroupBlock = new TransformBlock<LdapWrapper, LdapWrapper>(GPOGroupTasks.ParseGPOLocalGroups, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 10,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(processGpoLocalGroupBlock, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(processGpoLocalGroupBlock, linkOptions);
                }

                lastBlock = processGpoLocalGroupBlock;
            }

            //Start computer block here. We want to ping first
            if (!Options.Instance.SkipPing && Options.Instance.IsComputerCollectionSet())
            {
                var pingTask = new TransformBlock<LdapWrapper, LdapWrapper>(ComputerAvailableTasks.CheckSMBOpen, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 10,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(pingTask, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(pingTask, linkOptions);
                }

                lastBlock = pingTask;
            }

            if ((resolved & CollectionMethodResolved.Sessions) != 0)
            {
                var processSessionsBlock = new TransformBlock<LdapWrapper,LdapWrapper>(NetSessionTasks.ProcessNetSessions, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 10,
                    BoundedCapacity = 250
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(processSessionsBlock, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(processSessionsBlock, linkOptions);
                }

                lastBlock = processSessionsBlock;
            }

            if ((resolved & CollectionMethodResolved.LoggedOn) != 0)
            {
                var processLoggedonBlock = new TransformBlock<LdapWrapper, LdapWrapper>(LoggedOnTasks.ProcessLoggedOn, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 10,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(processLoggedonBlock, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(processLoggedonBlock, linkOptions);
                }

                lastBlock = processLoggedonBlock;
            }

            if ((resolved & CollectionMethodResolved.RDP) != 0 || (resolved & CollectionMethodResolved.DCOM) != 0 ||
                (resolved & CollectionMethodResolved.LocalAdmin) != 0 ||
                (resolved & CollectionMethodResolved.PSRemote) != 0)
            {
                var processLocalGroupBlock = new TransformBlock<LdapWrapper, LdapWrapper>(LocalGroupTasks.GetLocalGroupMembers, new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = 20,
                    BoundedCapacity = 250,
                    EnsureOrdered = false
                });

                if (!firstLinked)
                {
                    findTypeBlock.LinkTo(processLocalGroupBlock, linkOptions, (item) => item != null);
                    firstLinked = true;
                }
                else
                {
                    lastBlock.LinkTo(processLocalGroupBlock, linkOptions);
                }

                lastBlock = processLocalGroupBlock;
            }

            var outputBlock = new ActionBlock<LdapWrapper>(OutputTasks.WriteJsonOutput, new ExecutionDataflowBlockOptions
            {
                BoundedCapacity = 250,
                MaxDegreeOfParallelism = 1,
                EnsureOrdered = false
            });

            lastBlock?.LinkTo(outputBlock, linkOptions);
            
            if (lastBlock == null)
                findTypeBlock.Complete();
            else
                producer.StartProducer(findTypeBlock);
            OutputTasks.StartOutputTimer();
            outputBlock.Completion.Wait();
            CleanupTasks();
            compErrorTask?.Wait();
            
        }

        internal static void CleanupTasks()
        {
            OutputTasks.PrintStatus();
            OutputTasks.CompleteOutput();
            Cache.Instance.SaveCache();
        }
    }
}
