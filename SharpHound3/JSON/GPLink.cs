using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.JSON
{
    internal class GPLink
    {
        private string _guid;

        public bool? IsEnforced { get; set; }
        public string Guid
        {
            get => _guid;
            set => _guid = value.ToUpper();
        }
    }
}
