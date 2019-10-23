using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3.JSON
{
    internal class ComputerError
    {
        internal string ComputerName { get; set; }
        internal string Task { get; set; }
        internal string Error { get; set; }

        internal string ToCsv()
        {
            return $"{StringToCsvCell(ComputerName)}, {StringToCsvCell(Task)}, {StringToCsvCell(Error)}";
        }

        private static string StringToCsvCell(string str)
        {
            if (str == null)
                return null;
            var mustQuote = (str.Contains(",") || str.Contains("\"") || str.Contains("\r") || str.Contains("\n"));
            if (!mustQuote) return str;
            var sb = new StringBuilder();
            sb.Append("\"");
            foreach (var nextChar in str)
            {
                sb.Append(nextChar);
                if (nextChar == '"')
                    sb.Append("\"");
            }
            sb.Append("\"");
            return sb.ToString();
        }

    }
}
