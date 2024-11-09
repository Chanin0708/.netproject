// /Services/EmailService.cs
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;

namespace WebBackend.Services
{
    public class EmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string messageBody)
        {
            var email = new MimeMessage();
            email.From.Add(new MailboxAddress("No-Reply", _configuration["SMTP:From"]));
            email.To.Add(new MailboxAddress("", toEmail));
            email.Subject = subject;

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = messageBody
            };
            email.Body = bodyBuilder.ToMessageBody();

            using var smtp = new SmtpClient();

            // Using SecureSocketOptions.StartTls to establish a secure connection on port 587
            var host = _configuration["SMTP:Host"];
            var port = int.TryParse(_configuration["SMTP:Port"], out var parsedPort) ? parsedPort : 587;
            var username = _configuration["SMTP:Username"];
            var password = _configuration["SMTP:Password"];

            await smtp.ConnectAsync(host, port, SecureSocketOptions.StartTls);
            await smtp.AuthenticateAsync(username, password);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);
        }
    }
}
