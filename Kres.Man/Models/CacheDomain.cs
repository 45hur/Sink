using System;
using System.Collections.Generic;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CacheDomain
    {
        [ProtoMember(1)]
        public UInt64 Crc64 { get; set; }

        [ProtoMember(2)]
        public Int32 Accuracy { get; set; }

        [ProtoMember(3)]
        public IEnumerable<byte> Flags { get; set; }
    }
}
