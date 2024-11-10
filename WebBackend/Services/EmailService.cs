using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Hosting;
using System.IO;
using System.Threading.Tasks;

namespace WebBackend.Services
{
    public class EmailService
    {
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _environment;

        public EmailService(IConfiguration configuration, IWebHostEnvironment environment)
        {
            _configuration = configuration;
            _environment = environment;
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

            var host = _configuration["SMTP:Host"];
            var port = int.TryParse(_configuration["SMTP:Port"], out var parsedPort) ? parsedPort : 587;
            var username = _configuration["SMTP:Username"];
            var password = _configuration["SMTP:Password"];

            await smtp.ConnectAsync(host, port, SecureSocketOptions.StartTls);
            await smtp.AuthenticateAsync(username, password);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);
        }

        public async Task SendOtpEmailAsync(string toEmail, string firstName, string lastName, string otpCode, string referenceNumber )
        {
            var email = new MimeMessage();
            email.From.Add(new MailboxAddress("No-Reply", _configuration["SMTP:From"]));
            email.To.Add(new MailboxAddress("", toEmail));
            email.Subject = "CompanyName Mall : OTP";

            // Construct the path using IWebHostEnvironment
            var templatePath = Path.Combine(_environment.ContentRootPath, "Views", "Templates", "OtpEmailTemplate.html");

            if (!File.Exists(templatePath))
            {
                throw new FileNotFoundException("The email template file was not found.", templatePath);
            }

            var emailBody = await File.ReadAllTextAsync(templatePath);
            emailBody = emailBody.Replace("{FirstName}", firstName)
                                 .Replace("{LastName}", lastName)
                                 .Replace("{OTPCode}", otpCode)
                                 .Replace("{ReferenceNumber}", referenceNumber);

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = emailBody
            };
            email.Body = bodyBuilder.ToMessageBody();

            using var smtp = new SmtpClient();
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
