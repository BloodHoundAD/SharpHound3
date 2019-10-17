using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.JSON
{
    internal class Session
    {
        private string _computerName;
        private string _userName;

        public string UserName
        {
            get => _userName;
            set => _userName = value.ToUpper();
        }

        public string ComputerName
        {
            get => _computerName;
            set => _computerName = value.ToUpper();
        }
    }
}
