using System;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Timers;
using CommandLine;
using SharpHound3.Tasks;

namespace SharpHound3
{
    internal class SharpHound
    {
        /// <summary>
        /// Entry point for SharpHound. 
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        private static async Task Main(string[] args)
        {
            // Use the wonderful commandlineparser library to build our options.
            var parser = new Parser(with =>
            {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false;
                with.HelpWriter = Console.Error;
            });

            parser.ParseArguments<Options>(args).WithParsed(o =>
            {
                //We've successfully parsed arguments, lets do some options post-processing.
                var currentTime = DateTime.Now;
                var initString =
                    $"Initializing SharpHound at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}";
                Console.WriteLine(new string('-', initString.Length));
                Console.WriteLine(initString);
                Console.WriteLine(new string('-', initString.Length));
                Console.WriteLine();

                // Set the current user name for session collection.
                if (o.OverrideUserName != null)
                {
                    o.CurrentUserName = o.OverrideUserName;
                }
                else
                {
                    o.CurrentUserName = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
                }

                //Check some loop options
                if (o.Loop)
                {
                    //If loop is set, ensure we actually set options properly
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
            }).WithNotParsed(error =>
            {

            });

            parser.Dispose();

            var options = Options.Instance;
            if (options == null)
                return;

            // Check to make sure we actually have valid collection methods set
            if (!options.ResolveCollectionMethods())
            {
                return;
            }

            //If the user didn't specify a domain, pull the domain from DirectoryServices
            if (options.Domain == null)
                try
                {
                    options.Domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name.ToUpper();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    Console.WriteLine("Unable to determine user's domain. Please manually specify it with the --domain flag");
                    return;
                }
                

            //Check to make sure both LDAP options are set if either is set
            if ((options.LdapPassword != null && options.LdapUsername == null) ||
                (options.LdapUsername != null && options.LdapPassword == null))
            {
                Console.WriteLine("You must specify both LdapUsername and LdapPassword if using these options!");
                return;
            }

            //Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
            var searcher = Helpers.GetDirectorySearcher(options.Domain);
            var result = await searcher.GetOne("(objectclass=domain)", new[] { "objectsid" },
                SearchScope.Subtree);

            //If we get nothing back from LDAP, something is wrong
            if (result == null)
            {
                Console.WriteLine("LDAP Connection Test Failed. Check if you're in a domain context!");
                return;
            }

            var initialCompleted = false;
            var needsCancellation = false;
            Timer timer = null;
            var loopEnd = DateTime.Now;

            //If loop is set, set up our timer for the loop now
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

            //Create our Cache
            Cache.CreateInstance();

            //Start the computer error task (if specified)
            OutputTasks.StartComputerStatusTask();

            //Build our pipeline, and get the initial block to wait for completion.
            var pipelineCompletionTask = PipelineBuilder.GetBasePipelineForDomain(options.Domain);

            //Wait for output to complete
            await pipelineCompletionTask;

            //Wait for our output tasks to finish.
            await OutputTasks.CompleteOutput();

            //Mark our initial run as complete, signalling that we're now in the looping phase
            initialCompleted = true;

            if (needsCancellation)
            {
                Helpers.InvokeCancellation();
            }

            //Start looping if specified
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

                    //Special function to grab all the zip files created by looping and collapse them into a single file
                    await OutputTasks.CollapseLoopZipFiles();
                }
            }
            timer?.Dispose();

            //Program exit started. Save the cache file
            Cache.Instance.SaveCache();

            //And we're done!
            var currTime = DateTime.Now;
            Console.WriteLine();
            Console.WriteLine($"SharpHound Enumeration Completed at {currTime.ToShortTimeString()} on {currTime.ToShortDateString()}! Happy Graphing!");
            Console.WriteLine();
        }

        // Accessor function for the PS1 to work, do not change or remove
        public static void InvokeSharpHound(string[] args)
        {
            Main(args).Wait();
        }
    }
}
