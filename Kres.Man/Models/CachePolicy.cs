using System;
using System.Runtime.Serialization;
using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    [DataContract]
    public class CachePolicy
    {
        [ProtoMember(1)]
        [DataMember]
        public int Policy_id { get; set; }

        [ProtoMember(2)]
        [DataMember]
        public int Strategy { get; set; }

        [ProtoMember(3)]
        [DataMember]
        public int Audit { get; set; }

        [ProtoMember(4)]
        [DataMember]
        public int Block { get; set; }
    }
}
