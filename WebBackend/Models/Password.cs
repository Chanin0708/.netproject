
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;

namespace WebBackend.Models
{
    public class Password
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }

        [BsonElement("userid")]
        public string? UserId { get; set; }

        [BsonElement("password")]
        public string? EncryptedPassword { get; set; }

        [BsonElement("createdatetime")]
        public DateTime CreateDateTime { get; set; } = DateTime.UtcNow;
    }
}