using System;

namespace SharpHound3
{
    internal class FileExistsException : Exception
    {
        public FileExistsException(string message) : base(message)
        {
        }
    }

}
