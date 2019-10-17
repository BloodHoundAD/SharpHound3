using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.JSON;

namespace SharpHound3.LdapWrappers
{
    internal class GPO : LdapWrapper
    {
        internal GPO(SearchResultEntry entry) : base(entry)
        {
            RemoteDesktopUsers = new GroupMember[0];
            LocalAdmins = new GroupMember[0];
            DcomUsers = new GroupMember[0];
            AffectedComputers = new string[0];
        }

        public string[] AffectedComputers { get; set; }
        public GroupMember[] RemoteDesktopUsers { get; set; }
        public GroupMember[] LocalAdmins { get; set; }
        public GroupMember[] DcomUsers { get; set; }
    }
}
