using System.Collections.Generic;

namespace Kres.Man.Models
{
    public class View
    {
        public List<object> networks { get; set; }
        public List<string> legal { get; set; }
        public List<string> blacklist { get; set; }
        public List<string> accuracy { get; set; }
        public List<string> allow_bypass { get; set; }
    }

    public class PublicListenerConfig
    {
        public List<View> views { get; set; }
    }
}
