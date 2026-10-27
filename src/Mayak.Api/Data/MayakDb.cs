using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Data;

public sealed class MayakDb : DbContext
{
    public MayakDb(DbContextOptions<MayakDb> options) : base(options) { }

    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<Server> Servers => Set<Server>();
    public DbSet<ClusterIdentity> Cluster => Set<ClusterIdentity>();
    public DbSet<LoginRequest> LoginRequests => Set<LoginRequest>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<AuditEntry> Audit => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Account>(e =>
        {
            e.HasIndex(x => x.TelegramId).IsUnique();
            e.HasIndex(x => x.Email).IsUnique();
            e.Property(x => x.Role).HasMaxLength(16);
            e.HasMany(x => x.Devices).WithOne(x => x.Account!).HasForeignKey(x => x.AccountId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<Device>(e =>
        {
            e.HasIndex(x => x.AwgPublicKey).IsUnique();
            e.HasIndex(x => x.Ip).IsUnique();
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(16);
        });
        b.Entity<Server>(e =>
        {
            e.HasIndex(x => x.AgentTokenHash).IsUnique();
            e.Property(x => x.Role).HasMaxLength(8);
        });
        b.Entity<ClusterIdentity>(e => e.Property(x => x.Id).ValueGeneratedNever());
        b.Entity<LoginRequest>(e => e.Property(x => x.Id).HasMaxLength(64));
        b.Entity<Session>(e =>
        {
            e.HasKey(x => x.TokenHash);
            e.HasOne(x => x.Account).WithMany().HasForeignKey(x => x.AccountId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
