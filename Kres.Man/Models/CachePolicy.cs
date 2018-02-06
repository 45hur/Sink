using System;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CachePolicy
    {
        [ProtoMember(1)]
        public Int32 Policy_id { get; set; }

        [ProtoMember(2)]
        public Int32 Accuracy { get; set; }

        [ProtoMember(3)]
        public Int32 Audit { get; set; }

        [ProtoMember(4)]
        public Int32 Block { get; set; }
    }
}
