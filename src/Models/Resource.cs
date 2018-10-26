using Newtonsoft.Json;

namespace WebAppInteractingWithApiGw.Models
{
    public class Resource
    {
        [JsonProperty(PropertyName = "id")]
        public string Id { get; set; }

        [JsonProperty(PropertyName = "Code")]
        public string Code { get; set; }

        [JsonProperty(PropertyName = "HighLevelClassOfBusinessCode")]
        public string Definition { get; set; }
    }
}
