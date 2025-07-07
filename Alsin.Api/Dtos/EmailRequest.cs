using System.Text.Json.Serialization;

namespace Alsin.Api.Dtos
{
    public class EmailRequest
    {
            [JsonPropertyName("from")]
            public string From { get; set; }

            [JsonPropertyName("to")]
            public string To { get; set; }

            [JsonPropertyName("subject")]
            public string Subject { get; set; }

            [JsonPropertyName("html")]
            public string Html { get; set; }
    }
}
