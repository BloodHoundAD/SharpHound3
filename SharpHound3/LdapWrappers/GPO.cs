using System.DirectoryServices.Protocols;

namespace SharpHound3.LdapWrappers
{
    internal class GPO : LdapWrapper
    {
        internal GPO(SearchResultEntry entry) : base(entry)
        {

        }
    }
}
