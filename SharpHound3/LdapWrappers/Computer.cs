using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.JSON;

namespace SharpHound3.LdapWrappers
{
    internal class Computer : LdapWrapper
    {
        internal Computer(SearchResultEntry entry) : base(entry)
        {
            AllowedToAct = new string[0];
            AllowedToDelegate = new string[0];
            Sessions = new Session[0];
        }

        public string[] AllowedToDelegate { get; set; }

        public string[] AllowedToAct { get; set; }

        public string PrimaryGroupSid { get; set; }

        public Session[] Sessions { get; set; }
    }
}
