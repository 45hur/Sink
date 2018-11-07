using System.Collections.Generic;
using System.Runtime.Serialization;
using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    [DataContract]
    public class Cache
    {
        [ProtoMember(1)]
        [DataMember]
        public IEnumerable<CacheCustomList> CustomLists { get; set; }

        [ProtoMember(2)]
        [DataMember]
        public IEnumerable<CacheDomain> Domains { get; set; }

        [ProtoMember(3)]
        [DataMember]
        public IEnumerable<CacheIPRange> IPRanges { get; set; }

        [ProtoMember(4)]
        [DataMember]
        public IEnumerable<CachePolicy> Policies { get; set; }

        [DataMember]
        public bool Updated { get; set; }
    }
}
