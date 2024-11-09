// /DTOs/OtpVerificationRequest.cs
namespace WebBackend.DTOs
{
    public class OtpVerificationRequest
    {
        public string? Username { get; set; }
        public string? OtpCode { get; set; }
    }
}
