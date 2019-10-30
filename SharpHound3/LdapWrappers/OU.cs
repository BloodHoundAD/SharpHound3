using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.JSON;

namespace SharpHound3.LdapWrappers
{
    internal class OU : LdapWrapper
    {
        internal OU(SearchResultEntry entry) : base(entry)
        {
            Users = new string[0];
            Computers = new string[0];
            ChildOus = new string[0];
            RemoteDesktopUsers = new GenericMember[0];
            LocalAdmins = new GenericMember[0];
            DcomUsers = new GenericMember[0];
            PSRemoteUsers = new GenericMember[0];
            AffectedComputers = new string[0];
        }

        public bool ACLProtected { get; set; }
        public string[] Users { get; set; }
        public string[] Computers { get; set; }
        public string[] ChildOus { get; set; }
        public string[] AffectedComputers { get; set; }
        public GenericMember[] RemoteDesktopUsers { get; set; }
        public GenericMember[] LocalAdmins { get; set; }
        public GenericMember[] DcomUsers { get; set; }
        public GenericMember[] PSRemoteUsers { get; set; }
    }
}
