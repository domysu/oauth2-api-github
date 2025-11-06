using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Oauth2Api.Data
{
    public class AppDbContext : IdentityDbContext<IdentityUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        // Palik savo RefreshToken jei nori, bet paprasčiausiam veikimui nereikalinga
        // public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
        public DbSet<Repository> Repositories => Set<Repository>();
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<Repository>(e =>
            {
                e.HasKey(x => x.Id);
                e.HasIndex(x => new { x.UserId, x.GitHubId }).IsUnique();
                e.Property(x => x.Name).IsRequired().HasMaxLength(200);
                e.Property(x => x.FullName).IsRequired().HasMaxLength(400);
                e.Property(x => x.HtmlUrl).HasMaxLength(1000);
            });
        }
    }

    public class Repository
    {
        public int Id { get; set; }
        public string UserId { get; set; } = default!; // FK į AspNetUsers.Id
        public long GitHubId { get; set; } // originalus GitHub repo id
        public string Name { get; set; } = default!;
        public string FullName { get; set; } = default!;
        public string HtmlUrl { get; set; } = default!;
        public bool Private { get; set; }
        public string? Description { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
