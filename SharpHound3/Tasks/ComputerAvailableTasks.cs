using System;
using System.Threading.Tasks;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class ComputerAvailableTasks
    {
        internal static async Task<LdapWrapper> CheckSMBOpen(LdapWrapper wrapper)
        {
            if (wrapper is Computer computer)
            {
                if (Options.Instance.Stealth && !computer.IsStealthTarget)
                    return wrapper;

                if (Options.Instance.WindowsOnly)
                {
                    var os = wrapper.SearchResult.GetProperty("operatingsystem");
                    if (!(os?.IndexOf("windows", StringComparison.CurrentCultureIgnoreCase) > -1))
                    {
                        //If this isn't a windows computer, we'll mark is as such and we'll skip the following port scan since its not necessary
                        computer.IsWindows = false;

                        OutputTasks.AddComputerStatus(new ComputerStatus
                        {
                            ComputerName = computer.DisplayName,
                            Status = "NotWindows",
                            Task = "SMBCheck"
                        });
                        return wrapper;
                    }
                }

                if (Options.Instance.SkipPortScan)
                    return wrapper;

                computer.PingFailed = Helpers.CheckPort(computer.APIName, 445) == false;
                if (computer.PingFailed && Options.Instance.DumpComputerStatus)
                {
                    OutputTasks.AddComputerStatus(new ComputerStatus
                    {
                        ComputerName = computer.DisplayName,
                        Status = "SMBNotAvailable",
                        Task = "SMBCheck"
                    });
                }

                await Helpers.DoDelay();
            }

            return wrapper;
        }
    }
}
