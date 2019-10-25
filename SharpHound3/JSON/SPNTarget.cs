using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.JSON
{
    internal class SPNTarget
    {
        public string ComputerSid { get; set; }
        public int Port { get; set; }
        public string Service { get; set; }
    }
}
