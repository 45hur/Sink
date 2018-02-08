using System;
using System.Collections.Generic;
using System.Text;

using Kres.Man.Models;

namespace Kres.Man
{
    internal class CacheLiveStorage
    {
        public static Cache CoreCache { get; set; }
        public static CacheIPRange UdtCache { get; set; }
    }
}
