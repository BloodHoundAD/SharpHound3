using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class ComputerAvailableTasks
    {
        internal static LdapWrapper CheckComputerAlive(LdapWrapper wrapper)
        {
            if (wrapper is Computer computer)
            {
                computer.PingFailed = Helpers.PingHost(computer.APIName, 445) == false;
                if (computer.PingFailed && Options.Instance.DumpComputerErrors)
                {
                    OutputTasks.AddComputerError(new ComputerError
                    {
                        ComputerName = computer.DisplayName,
                        Error = "SMBNotAvailable",
                        Task = "Ping"
                    });
                }
            }

            return wrapper;
        }
    }
}
