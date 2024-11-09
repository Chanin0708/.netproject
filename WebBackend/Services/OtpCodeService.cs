// /Services/OtpCodeService.cs
using System;
using System.Threading.Tasks;
using MongoDB.Driver;
using WebBackend.Models;

namespace WebBackend.Services
{
    public class OtpCodeService
    {
        private readonly IMongoCollection<OtpCode> _otpCodes;

        public OtpCodeService(IMongoDatabase database)
        {
            _otpCodes = database.GetCollection<OtpCode>("OtpCodes");
        }

        public async Task InsertOtpCodeAsync(string userId, string code, DateTime expiryInUtcPlus7)
        {
            // Convert the provided expiry date to UTC
            DateTime expiryUtc = TimeZoneInfo.ConvertTimeToUtc(expiryInUtcPlus7, TimeZoneInfo.FindSystemTimeZoneById("SE Asia Standard Time"));

            // Create the OtpCode object with the UTC expiry date
            var otpCode = new OtpCode
            {
                UserId = userId,
                Code = code,
                Expiry = expiryUtc // Store in UTC
            };

            // Insert into MongoDB
            await _otpCodes.InsertOneAsync(otpCode);
        }
    }
}
