using System;

namespace SharpHound3
{
    internal class ControlNotSupportedException : Exception
    {
    }

    internal class FileExistsException : Exception
    {
        public FileExistsException(string message) : base(message)
        {
        }
    }

}
