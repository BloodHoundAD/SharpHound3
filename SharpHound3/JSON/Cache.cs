using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHound3.JSON
{
    internal sealed class Cache
    {
        private readonly ConcurrentDictionary<string, string> applicationCache;
        
        private static readonly Lazy<Cache> instance = new Lazy<Cache>();

        internal static Cache Instance => instance.Value;

        private Cache()
        {
            applicationCache = new ConcurrentDictionary<string, string>();
        }

        internal bool Get(string key, out string value)
        {
            var success = applicationCache.TryGetValue(key, out value);
            return success;
        }

        internal void Add(string key, string value)
        {
            applicationCache.TryAdd(key, value);
        }
    }
}
