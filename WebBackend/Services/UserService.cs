// /Services/UserService.cs
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using WebBackend.Data;
using WebBackend.Models;

namespace WebBackend.Services
{
    public class UserService
    {
        private readonly WebBackendMongoDbContext _context;
        private readonly string _encryptionKey;

        public UserService(WebBackendMongoDbContext context, IConfiguration configuration)
        {
            _context = context;
            _encryptionKey = configuration["EncryptionKey"] ?? throw new ArgumentNullException("EncryptionKey", "Encryption key is missing in configuration.");
        }

        public string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password), "Password cannot be null or empty");

            using var sha = SHA256.Create();
            var hashed = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashed);
        }

        public bool VerifyPassword(string password, string storedHash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash))
                return false;

            return HashPassword(password) == storedHash;
        }

        // public string EncryptPassword(string plainTextPassword)
        // {
        //     var key = Encoding.UTF8.GetBytes(_encryptionKey.Substring(0, 32)); // Ensure key is 32 bytes for AES-256
        //     using var aes = Aes.Create();
        //     aes.Key = key;
        //     aes.GenerateIV();
        //     using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        //     var plainBytes = Encoding.UTF8.GetBytes(plainTextPassword);
        //     var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        //     var ivWithEncrypted = new byte[aes.IV.Length + encryptedBytes.Length];
        //     Array.Copy(aes.IV, 0, ivWithEncrypted, 0, aes.IV.Length);
        //     Array.Copy(encryptedBytes, 0, ivWithEncrypted, aes.IV.Length, encryptedBytes.Length);

        //     return Convert.ToBase64String(ivWithEncrypted);
        // }

        public string EncryptPassword(string plainTextPassword)
        {
            var key = Encoding.UTF8.GetBytes(_encryptionKey.Substring(0, 32)); // AES-256 key size

            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            var plainBytes = Encoding.UTF8.GetBytes(plainTextPassword);
            var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            // Combine IV and encrypted data
            var ivWithEncrypted = new byte[aes.IV.Length + encryptedBytes.Length];
            Array.Copy(aes.IV, 0, ivWithEncrypted, 0, aes.IV.Length);
            Array.Copy(encryptedBytes, 0, ivWithEncrypted, aes.IV.Length, encryptedBytes.Length);

            return Convert.ToBase64String(ivWithEncrypted);
        }

        public string DecryptPassword(string encryptedPassword)
        {
            var fullCipher = Convert.FromBase64String(encryptedPassword);

            // AES block size is 16 bytes (for IV)
            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            // Extract IV and cipher text
            Array.Copy(fullCipher, 0, iv, 0, iv.Length);
            Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            var key = Encoding.UTF8.GetBytes(_encryptionKey.Substring(0, 32)); // AES-256 requires a 32-byte key

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            var decryptedBytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);

            return Encoding.UTF8.GetString(decryptedBytes);
        }


        public async Task SaveEncryptedPasswordAsync(string userId, string password)
        {
            var passwordEntry = new Password
            {
                UserId = userId,
                EncryptedPassword = password,
                CreateDateTime = DateTime.Now.AddHours(7)
            };

            await _context.Passwords.InsertOneAsync(passwordEntry);
        }


        public string DecryptUserPassword(string encryptedPassword)
        {
            return DecryptPassword(encryptedPassword);
        }

        public string DecryptPasswordCollectionPassword(string encryptedPassword)
        {
            return DecryptPassword(encryptedPassword);
        }

    }
}
