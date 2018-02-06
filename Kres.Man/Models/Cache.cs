using System.Collections.Generic;
using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class Cache
    {
        [ProtoMember(1)]
        public IEnumerable<CacheCustomLists> CustomList { get; set; }

        [ProtoMember(2)]
        public IEnumerable<CacheDomains> Domains { get; set; }

        [ProtoMember(3)]
        public IEnumerable<CacheIPRanges> IPRanges { get; set; }

        [ProtoMember(4)]
        public IEnumerable<CachePolicy> Policy { get; set; }
    }
}
