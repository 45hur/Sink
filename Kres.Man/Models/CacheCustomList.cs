using System;
using System.Collections.Generic;
using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CacheCustomList
    {
        [ProtoMember(1)]
        public string Identity { get; set; }

        [ProtoMember(2)]
        public IEnumerable<string> WhiteList { get; set; }

        [ProtoMember(3)]
        public IEnumerable<string> BlackList { get; set; }

        [ProtoMember(4)]
        public int PolicyId { get; set; }
    }
}
