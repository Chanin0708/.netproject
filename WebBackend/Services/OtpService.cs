// /Services/OtpService.cs
using System;
using System.Threading.Tasks;

namespace WebBackend.Services
{
    public class OtpService
    {
        private static readonly Random _random = new Random();
        public string GenerateOtp()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        public string GenerateReferenceNo()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, 6)
                .Select(s => s[_random.Next(s.Length)]).ToArray());
        }

        public Task SendOtp(string email, string otp)
        {
            // Implement email sending logic here
            Console.WriteLine($"Sending OTP {otp} to email {email}");
            return Task.CompletedTask;
        }
    }
}
