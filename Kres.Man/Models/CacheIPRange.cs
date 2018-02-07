using System;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CacheIPRange
    {
        [ProtoMember(1)]
        public Int128 IpFrom { get; set; }

        [ProtoMember(2)]
        public Int128 IpTo { get; set; }

        [ProtoMember(3)]
        public string Identity { get; set; }

        [ProtoMember(4)]
        public Int32 PolicyId { get; set; }
    }
}
