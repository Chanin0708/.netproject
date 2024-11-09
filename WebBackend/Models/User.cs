// /Models/User.cs
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace WebBackend.Models
{

    public class User
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? UserId { get; set; }

        [BsonElement("username")]
        public string? Username { get; set; }

        [BsonElement("email")]
        public string? Email { get; set; }

        [BsonElement("firstname")]
        public string? FirstName { get; set; }

        [BsonElement("lastname")]
        public string? LastName { get; set; }

        [BsonElement("createdatetime")]
        public DateTime CreateDateTime { get; set; } = DateTime.UtcNow;

        [BsonElement("countlogin")]
        public int CountLogin { get; set; } = 0;

        [BsonElement("statusaccount")]
        public string StatusAccount { get; set; } = "Active";

        [BsonElement("lastupdate")]
        public DateTime LastUpdate { get; set; } = DateTime.UtcNow;

        [BsonElement("twofactorauthen")]
        public bool TwoFactorAuthen { get; set; } = false;

        [BsonElement("twofactorauthentype")]
        public string? TwoFactorAuthentype { get; set; } // "email" or "google authen"

        [BsonElement("secretkey")]
        public string? SecretKey { get; set; } 

        [BsonElement("typeuser")]
        public string TypeUser { get; set; } = "Standard";

        // New PasswordHash property
        [BsonElement("passwordhash")]
        public string? PasswordHash { get; set; }
    }
}