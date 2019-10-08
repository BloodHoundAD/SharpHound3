using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.LdapWrappers
{
    internal class User : LdapWrapper
    {
        internal User(SearchResultEntry entry) : base(entry)
        {
        }

        public string[] AllowedToDelegate { get; set; }
    }
}
