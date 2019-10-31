using System;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
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

            OutputTasks.StartComputerStatusTask();

            var pipeline = PipelineBuilder.GetBasePipelineForDomain(Options.Instance.Domain);
            await pipeline;

            
            await OutputTasks.CompleteOutput();
            Cache.Instance.SaveCache();
        }
    }
}
