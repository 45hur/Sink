using System;
using System.Collections.Concurrent;
using System.Runtime.Serialization;

using Kres.Man.Models;

namespace Kres.Man
{
    [DataContract]
    internal class CacheLiveStorage
    {
        [DataMember]
        public static Cache CoreCache { get; set; }
        [DataMember]
        public static ConcurrentDictionary<string, CacheIPRange> UdpCache { get; set; }
    }
}
