using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.JSON
{
    internal class ACL
    {
        public string PrincipalSID { get; set; }
        public string RightName { get; set; }
        
        public string AceType { get; set; }

        public override string ToString()
        {
            return $"{RightName} - {PrincipalSID}";
        }
    }
}
