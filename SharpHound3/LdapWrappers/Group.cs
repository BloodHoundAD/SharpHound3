using System.DirectoryServices.Protocols;
using SharpHound3.JSON;

namespace SharpHound3.LdapWrappers
{
    internal class Group : LdapWrapper
    {
        internal Group(SearchResultEntry entry) : base(entry)
        {
            Members = new GenericMember[0];
        }

        public GenericMember[] Members { get; set; }
    }
}
