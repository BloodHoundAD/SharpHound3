using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.LdapWrappers
{
    internal class Group : LdapWrapper
    {
        internal Group(SearchResultEntry entry) : base(entry)
        {
        }
    }
}
