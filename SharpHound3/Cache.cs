using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Newtonsoft.Json;
using SharpHound3.Enums;

namespace SharpHound3
{
    internal class Cache
    {
        [JsonProperty]
        private ConcurrentDictionary<string, ResolvedPrincipal> _resolvedPrincipalDictionary;

        [JsonProperty]
        private ConcurrentDictionary<string, string[]> _globalCatalogDictionary;

        [JsonProperty]
        private ConcurrentDictionary<string, LdapTypeEnum> _sidTypeDictionary;

        [JsonIgnore]
        private readonly Mutex _bhMutex;

        [JsonIgnore]
        public static Cache Instance => CacheInstance;

        [JsonIgnore]
        private static Cache CacheInstance { get; set; }

        internal static void CreateInstance()
        {
            CacheInstance = new Cache();
            CacheInstance.LoadCache();
        }

        private Cache()
        {
            _bhMutex = new Mutex(false, $"MUTEX:{GetBase64MachineID()}");
        }

        internal bool GetPrincipal(string key, out ResolvedPrincipal value)
        {
            return _resolvedPrincipalDictionary.TryGetValue(key.ToUpper(), out value);
        }

        internal bool GetGlobalCatalogMatches(string key, out string[] sids)
        {
            return _globalCatalogDictionary.TryGetValue(key.ToUpper(), out sids);
        }

        internal bool GetSidType(string key, out LdapTypeEnum type)
        {
            return _sidTypeDictionary.TryGetValue(key.ToUpper(), out type);
        }

        internal void Add(string key, ResolvedPrincipal value)
        {
            _resolvedPrincipalDictionary.TryAdd(key.ToUpper(), value);
        }

        internal void Add(string key, string[] domains)
        {
            _globalCatalogDictionary.TryAdd(key.ToUpper(), domains);
        }

        internal void Add(string key, LdapTypeEnum type)
        {
            _sidTypeDictionary.TryAdd(key, type);
        }

        internal void LoadCache()
        {
            if (Options.Instance.InvalidateCache)
            {
                _globalCatalogDictionary = new ConcurrentDictionary<string, string[]>();
                _resolvedPrincipalDictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
                _sidTypeDictionary = new ConcurrentDictionary<string, LdapTypeEnum>();
                Console.WriteLine("Cache Invalidated: 0 Objects in Cache");
                return;
            }

            var fileName = GetCacheFileName();

            if (!File.Exists(fileName))
            {
                _globalCatalogDictionary = new ConcurrentDictionary<string, string[]>();
                _resolvedPrincipalDictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
                _sidTypeDictionary = new ConcurrentDictionary<string, LdapTypeEnum>();
                Console.WriteLine("Cache File not Found: 0 Objects in cache");
                return;
            }

            try
            {
                _bhMutex.WaitOne();
                var bytes = File.ReadAllBytes(fileName);
                var json = new UTF8Encoding(true).GetString(bytes);
                CacheInstance = JsonConvert.DeserializeObject<Cache>(json);
                Console.WriteLine($"Cache File Found! Loaded {CacheInstance._resolvedPrincipalDictionary.Count + CacheInstance._globalCatalogDictionary.Count + CacheInstance._sidTypeDictionary.Count} Objects in cache");
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

            var jsonCache = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(CacheInstance));
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
