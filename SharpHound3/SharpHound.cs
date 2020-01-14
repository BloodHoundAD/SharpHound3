using System;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using System.Timers;
using CommandLine;
using SharpHound3.Enums;
using SharpHound3.LdapWrappers;
using SharpHound3.Tasks;

namespace SharpHound3
{
    internal class SharpHound
    {
        private static async Task Main(string[] args)
        {
            //TODO: Trusts
            var parser = new Parser(with =>
            {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false;
                with.HelpWriter = Console.Error;
            });

            parser.ParseArguments<Options>(args).WithParsed(o =>
            {
                var currentTime = DateTime.Now;
                var initString =
                    $"Initializing SharpHound at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}";
                Console.WriteLine(new string('-', initString.Length));
                Console.WriteLine(initString);
                Console.WriteLine(new string('-', initString.Length));
                Console.WriteLine();

                if (o.OverrideUserName != null)
                {
                    o.CurrentUserName = o.OverrideUserName;
                }
                else
                {
                    o.CurrentUserName = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
                }

                if (o.Loop)
                {
                    if (o.LoopDuration == TimeSpan.Zero)
                    {
                        Console.WriteLine("Loop specified without a duration. Defaulting to 2 hours!");
                        o.LoopDuration = TimeSpan.FromHours(2);
                    }

                    if (o.LoopInterval == TimeSpan.Zero)
                    {
                        o.LoopInterval = TimeSpan.FromSeconds(30);
                    }
                }

                Options.Instance = o;
            }).WithNotParsed(error => {

            });

            parser.Dispose();

            var options = Options.Instance;
            if (options == null)
                return;

            if (!options.ResolveCollectionMethods())
            {
                return;
            }

            if (options.Domain == null)
                options.Domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;

            var searcher = Helpers.GetDirectorySearcher(options.Domain);
            var result = await searcher.GetOne($"(objectsid={Helpers.ConvertSidToHexSid("S-1-5-32-544")})", new[] {"objectsid"},
                SearchScope.Subtree);

            if (result == null)
            {
                Console.WriteLine("LDAP Connection Test Failed. Check if you're in a domain context!");
                return;
            }

            var initialCompleted = false;
            var needsCancellation = false;
            Timer timer = null;
            var loopEnd = DateTime.Now;
            if (options.Loop)
            {
                loopEnd = loopEnd.AddMilliseconds(options.LoopDuration.TotalMilliseconds);
                timer = new Timer();
                timer.Elapsed += (sender, eventArgs) =>
                {
                    if (initialCompleted)
                        Helpers.InvokeCancellation();
                    else
                        needsCancellation = true;
                };
                timer.Interval = options.LoopDuration.TotalMilliseconds;
                timer.AutoReset = false;
                timer.Start();
            }

            Cache.CreateInstance();

            OutputTasks.StartComputerStatusTask();
            var pipelineCompletionTask = PipelineBuilder.GetBasePipelineForDomain(options.Domain);
            await pipelineCompletionTask;
            await OutputTasks.CompleteOutput();
            initialCompleted = true;

            if (needsCancellation)
            {
                Helpers.InvokeCancellation();
            }

            if (Options.Instance.Loop)
            {
                if (Helpers.GetCancellationToken().IsCancellationRequested)
                {
                    Console.WriteLine("Skipping looping because loop duration has already passed");
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("Waiting 30 seconds before starting loops");
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(30), Helpers.GetCancellationToken());
                    }
                    catch (TaskCanceledException)
                    {
                        Console.WriteLine("Skipped wait because loop duration has completed!");
                    }

                    if (!Helpers.GetCancellationToken().IsCancellationRequested)
                    {
                        Console.WriteLine();
                        Console.WriteLine($"Loop Enumeration Methods: {options.GetLoopCollectionMethods()}");
                        Console.WriteLine($"Looping scheduled to stop at {loopEnd.ToLongTimeString()} on {loopEnd.ToShortDateString()}");
                        Console.WriteLine();
                    }
                    
                    var count = 0;
                    while (!Helpers.GetCancellationToken().IsCancellationRequested)
                    {
                        count++;
                        var currentTime = DateTime.Now;
                        Console.WriteLine($"Starting loop #{count} at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}");
                        Helpers.StartNewRun();
                        pipelineCompletionTask = PipelineBuilder.GetLoopPipelineForDomain(Options.Instance.Domain);
                        await pipelineCompletionTask;
                        await OutputTasks.CompleteOutput();
                        if (!Helpers.GetCancellationToken().IsCancellationRequested)
                        {
                            Console.WriteLine();
                            Console.WriteLine($"Waiting {options.LoopInterval.TotalSeconds} seconds for next loop");
                            Console.WriteLine();
                            try
                            {
                                await Task.Delay(options.LoopInterval, Helpers.GetCancellationToken());
                            }
                            catch (TaskCanceledException)
                            {
                                Console.WriteLine("Skipping wait as loop duration has expired");
                            }
                        }
                    }

                    if (count > 0)
                        Console.WriteLine($"Looping finished! Looped a total of {count} times");

                    await OutputTasks.CollapseLoopZipFiles();
                }
            }
            timer?.Dispose();

            Cache.Instance.SaveCache();

            Console.WriteLine();
            Console.WriteLine("SharpHound Enumeration Completed! Happy Graphing!");
            Console.WriteLine();
        }

        // Accessor function for the PS1 to work, do not change or remove
        public static async void InvokeSharpHound(string[] args)
        {
            await Main(args);
        }
    }
}
