using System;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CachePolicy
    {
        [ProtoMember(1)]
        public int Policy_id { get; set; }

        [ProtoMember(2)]
        public int Strategy { get; set; }

        [ProtoMember(3)]
        public int Audit { get; set; }

        [ProtoMember(4)]
        public int Block { get; set; }
    }
}
