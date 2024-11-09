// /Services/OtpService.cs
using System;
using System.Threading.Tasks;

namespace WebBackend.Services
{
    public class OtpService
    {
        public string GenerateOtp()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        public Task SendOtp(string email, string otp)
        {
            // Implement email sending logic here
            Console.WriteLine($"Sending OTP {otp} to email {email}");
            return Task.CompletedTask;
        }
    }
}
