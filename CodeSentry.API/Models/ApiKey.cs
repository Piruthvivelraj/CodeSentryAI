using System.ComponentModel.DataAnnotations;

namespace CodeSentry.API.Models;

public class ApiKey
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string UserId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string KeyValue { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsed { get; set; }
}
