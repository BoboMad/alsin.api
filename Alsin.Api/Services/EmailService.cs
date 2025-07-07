using Alsin.Api.Dtos;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;

namespace Alsin.Api.Services
{
    public class EmailService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _config;
        private readonly string _frontendBaseUrl;
        public EmailService(HttpClient httpClient, IConfiguration config)
        {
            _httpClient = httpClient;
            _config = config;
            _frontendBaseUrl = config["Frontend:BaseUrl"] ?? throw new ArgumentNullException("Frontend:BaseUrl config is missing.");
        }

        public async Task SendConfirmationEmail(string email, string htmlContent)
        {
            var request = new EmailRequest
            {
                From = "Alsin <noreply@forsberg.cc>",
                To = email,
                Subject = "Confirm your email",
                Html = htmlContent
            };

            var httpRequest = new HttpRequestMessage(HttpMethod.Post, "https://api.resend.com/emails")
            {
                Content = JsonContent.Create(request)
            };

            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _config["Resend:ApiKey"]);

            var response = await _httpClient.SendAsync(httpRequest);

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception("Failed to send email");
            }
        }

        /// <summary>
        /// Renders a specific email template by calling the frontend route.
        /// </summary>
        /// <param name="templateEndpoint">Path after `/api/`, e.g. `render-confirmation-email`</param>
        /// <param name="queryParams">Dictionary of query parameters like name, confirmationUrl</param>
        public async Task<string> RenderEmailTemplateAsync(string templateEndpoint, Dictionary<string, string> queryParams)
        {
            var query = string.Join("&", queryParams.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
            var url = $"{_frontendBaseUrl}/api/{templateEndpoint}?{query}";

            var response = await _httpClient.GetAsync(url);

            if (!response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                throw new Exception($"Failed to render email template from frontend: {response.StatusCode} - {content}");
            }

            return await response.Content.ReadAsStringAsync();
        }
    }
}
