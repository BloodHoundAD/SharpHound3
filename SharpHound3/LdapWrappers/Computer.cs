using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.LdapWrappers
{
    internal class Computer : LdapWrapper
    {
        internal Computer(SearchResultEntry entry) : base(entry)
        {
        }

        public string[] AllowedToDelegate { get; set; }

        public string[] AllowedToAct { get; set; }

        public string PrimaryGroupSid { get; set; }
    }
}
