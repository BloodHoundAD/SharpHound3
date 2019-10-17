using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.LdapWrappers
{
    internal class OU : LdapWrapper
    {
        internal OU(SearchResultEntry entry) : base(entry)
        {
            Users = new string[0];
            Computers = new string[0];
            ChildOus = new string[0];
        }

        public bool ACLProtected { get; set; }

        public string[] Users { get; set; }
        public string[] Computers { get; set; }
        public string[] ChildOus { get; set; }
    }
}
