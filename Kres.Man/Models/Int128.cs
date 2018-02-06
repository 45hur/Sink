using System;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class Int128
    {
        [ProtoMember(1)]
        public Int64 Hi { get; set; }
        [ProtoMember(2)]
        public Int64 Low { get; set; }
    }
}
