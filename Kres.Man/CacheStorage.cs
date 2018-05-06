using System;
using System.Collections.Concurrent;
using System.Text;

using Kres.Man.Models;

namespace Kres.Man
{
    internal class CacheLiveStorage
    {
        public static Cache CoreCache { get; set; }
        public static ConcurrentDictionary<string, CacheIPRange> UdpCache { get; set; }
    }
}
