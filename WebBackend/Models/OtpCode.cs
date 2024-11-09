// /Models/OtpCode.cs
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace WebBackend.Models
{
    public class OtpCode
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }
        public string? UserId { get; set; }
        public string? Code { get; set; }
        public DateTime Expiry { get; set; }
    }
}
