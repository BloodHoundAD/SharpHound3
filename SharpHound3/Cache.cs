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
        private ConcurrentDictionary<string, object> _dictionary;

        [JsonIgnore]
        private static readonly Lazy<Cache> CacheInstance = new Lazy<Cache>(() => new Cache());
        [JsonIgnore]
        private readonly Mutex _bhMutex;

        [JsonIgnore]
        public static Cache Instance => CacheInstance.Value;

        private Cache()
        {
            LoadCache();
            _bhMutex = new Mutex(false, $"MUTEX:{GetBase64MachineID()}");
        }

        internal bool GetPrincipal(string key, out ResolvedPrincipal value)
        {
            var success = _dictionary.TryGetValue($"RP:{key}", out var principal);
            value = principal as ResolvedPrincipal;
            return success;
        }

        internal bool GetGlobalCatalogMatches(string key, out string[] sids)
        {
            var success = _dictionary.TryGetValue($"GC:{key}", out var possible);
            sids = possible as string[];
            return success;
        }

        internal void Add(string key, ResolvedPrincipal value)
        {
            _dictionary.TryAdd($"RP:{key}", value);
        }

        internal void Add(string key, string[] domains)
        {
            _dictionary.TryAdd($"GC:{key}", domains);
        }

        internal void LoadCache()
        {
            if (Options.Instance.InvalidateCache)
            {
                _dictionary = new ConcurrentDictionary<string, object>();
                return;
            }

            var fileName = GetCacheFileName();

            if (!File.Exists(fileName))
            {
                _dictionary = new ConcurrentDictionary<string, object>();
                return;
            }

            try
            {
                _bhMutex.WaitOne();
                var bytes = File.ReadAllBytes(fileName);
                var json = new UTF8Encoding(true).GetString(bytes);

                _dictionary = JsonConvert.DeserializeObject<ConcurrentDictionary<string, object>>(json);
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
