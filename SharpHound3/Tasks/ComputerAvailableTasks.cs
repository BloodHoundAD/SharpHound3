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
                computer.PingFailed = Helpers.PingHost(computer.APIName, 445) == false;
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
