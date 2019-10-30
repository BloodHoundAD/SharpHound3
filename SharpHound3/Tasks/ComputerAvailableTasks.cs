using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class ComputerAvailableTasks
    {
        internal static LdapWrapper CheckSMBOpen(LdapWrapper wrapper)
        {
            if (wrapper is Computer computer)
            {
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
            }

            return wrapper;
        }
    }
}
