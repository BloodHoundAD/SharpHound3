using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Newtonsoft.Json;
using SharpHound3.Enums;

namespace SharpHound3
{
    internal class Cache
    {
        private ConcurrentDictionary<string, ResolvedPrincipal> _dictionary;
        private static readonly Lazy<Cache> CacheInstance = new Lazy<Cache>(() => new Cache());
        private readonly Mutex _bhMutex;

        public static Cache Instance => CacheInstance.Value;

        private Cache()
        {
            LoadCache();
            _bhMutex = new Mutex(false, $"MUTEX:{GetBase64MachineID()}");
        }

        internal bool Get(string key, out ResolvedPrincipal value)
        {
            return _dictionary.TryGetValue(key, out value);
        }

        internal void Add(string key, ResolvedPrincipal value)
        {
            _dictionary.TryAdd(key, value);
        }

        internal void LoadCache()
        {
            if (Options.Instance.InvalidateCache)
            {
                _dictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
                return;
            }

            var fileName = GetCacheFileName();

            if (!File.Exists(fileName))
            {
                _dictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
                return;
            }

            try
            {
                _bhMutex.WaitOne();
                var bytes = File.ReadAllBytes(fileName);
                var json = new UTF8Encoding(true).GetString(bytes);
                _dictionary = JsonConvert.DeserializeObject<ConcurrentDictionary<string,ResolvedPrincipal>>(json);
            }
            finally
            {
                _bhMutex.ReleaseMutex();
            }
        }

        private string GetCacheFileName()
        {
            var baseFilename = Options.Instance.CacheFilename ?? $"{GetBase64MachineID()}.bin";
            var finalFilename = Path.Combine(Options.Instance.OutputDirectory, baseFilename);

            return finalFilename;
        }

        internal void SaveCache()
        {
            if (Options.Instance.NoSaveCache)
            {
                return;
            }

            var jsonCache = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(_dictionary));
            var finalFilename = GetCacheFileName();

            try
            {
                _bhMutex.WaitOne();
                using (var stream =
                    new FileStream(finalFilename, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None))
                {
                    stream.Write(jsonCache, 0, jsonCache.Length);
                }
            }
            finally
            {
                _bhMutex.ReleaseMutex();
            }
        }

        private static string GetBase64MachineID()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography"))
                {
                    if (key == null)
                    {
                        return $"{Helpers.Base64(Environment.MachineName)}";
                    }

                    var guid = key.GetValue("MachineGuid") as string;
                    return Helpers.Base64(guid);
                }
            }
            catch
            {
                return $"{Helpers.Base64(Environment.MachineName)}";
            }
        }
    }

    public class ResolvedPrincipal
    {
        public string ObjectIdentifier { get; set; }
        public LdapTypeEnum ObjectType { get; set; }
    }
}
