// /Data/MongoDbContext.cs
using MongoDB.Driver;
using Microsoft.Extensions.Configuration;
using WebBackend.Models;

namespace WebBackend.Data
{
    public class WebBackendMongoDbContext
    {
        private readonly IMongoDatabase _database;

        public WebBackendMongoDbContext(IConfiguration config)
        {
            var client = new MongoClient(config["MongoDB:ConnectionString"]);
            _database = client.GetDatabase(config["MongoDB:DatabaseName"]);
        }

        public IMongoCollection<User> Users => _database.GetCollection<User>("Users");
        public IMongoCollection<Password> Passwords => _database.GetCollection<Password>("Passwords");
        public IMongoCollection<OtpCode> OtpCodes => _database.GetCollection<OtpCode>("OtpCodes");
    }
}
