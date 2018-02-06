using System;
using System.Collections.Generic;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CacheDomains
    {
        [ProtoMember(1)]
        public UInt64 crc64 { get; set; }

        [ProtoMember(2)]
        public Int32 accuracy { get; set; }

        [ProtoMember(3)]
        public IEnumerable<byte> flags { get; set; }
    }
}
