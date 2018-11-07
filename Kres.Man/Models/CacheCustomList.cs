using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    [DataContract]
    public class CacheCustomList
    {
        [ProtoMember(1)]
        [DataMember]
        public string Identity { get; set; }

        [ProtoMember(2)]
        [DataMember]
        public IEnumerable<string> WhiteList { get; set; }

        [ProtoMember(3)]
        [DataMember]
        public IEnumerable<string> BlackList { get; set; }

        [ProtoMember(4)]
        [DataMember]
        public int PolicyId { get; set; }
    }
}
