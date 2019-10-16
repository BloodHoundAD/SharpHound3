using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpHound3.Enums;

namespace SharpHound3.JSON
{
    internal class GroupMember
    {
        public string MemberName { get; set; }
        public LdapTypeEnum MemberType { get;set; }

        public override string ToString()
        {
            return $"{MemberName} - {MemberType}";
        }
    }
}
