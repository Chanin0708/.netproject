// /Services/PasswordService.cs
using MongoDB.Driver;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using WebBackend.Data;
using WebBackend.Models;

namespace WebBackend.Services
{
    public class PasswordService
    {
        private readonly WebBackendMongoDbContext _context;
        private readonly string _encryptionKey;

        public PasswordService(WebBackendMongoDbContext context, IConfiguration configuration)
        {
            _context = context;

            // Ensure the encryption key is not null
            _encryptionKey = configuration["EncryptionKey"]
                             ?? throw new ArgumentNullException("EncryptionKey", "Encryption key is missing in configuration.");
        }

        public string EncryptPassword(string plainTextPassword)
        {
            var key = Encoding.UTF8.GetBytes(_encryptionKey.Substring(0, 32)); // Ensure key is 32 bytes for AES-256
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            var plainBytes = Encoding.UTF8.GetBytes(plainTextPassword);
            var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            var ivWithEncrypted = new byte[aes.IV.Length + encryptedBytes.Length];
            Array.Copy(aes.IV, 0, ivWithEncrypted, 0, aes.IV.Length);
            Array.Copy(encryptedBytes, 0, ivWithEncrypted, aes.IV.Length, encryptedBytes.Length);

            return Convert.ToBase64String(ivWithEncrypted);
        }

        public async Task SaveEncryptedPasswordAsync(string userId, string password)
        {
            var encryptedPassword = EncryptPassword(password);
            var passwordEntry = new Password
            {
                UserId = userId,
                EncryptedPassword = encryptedPassword,
                CreateDateTime = DateTime.UtcNow
            };

            await _context.Passwords.InsertOneAsync(passwordEntry);
        }
    }
}
