using System.Collections.Generic;
using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class Cache
    {
        [ProtoMember(1)]
        public IEnumerable<CacheCustomList> CustomLists { get; set; }

        [ProtoMember(2)]
        public IEnumerable<CacheDomain> Domains { get; set; }

        [ProtoMember(3)]
        public IEnumerable<CacheIPRange> IPRanges { get; set; }

        [ProtoMember(4)]
        public IEnumerable<CachePolicy> Policies { get; set; }
    }
}
