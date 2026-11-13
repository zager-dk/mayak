using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Data;

public sealed class MayakDb : DbContext
{
    public MayakDb(DbContextOptions<MayakDb> options) : base(options) { }

    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<Server> Servers => Set<Server>();
    public DbSet<ExitEndpoint> ExitEndpoints => Set<ExitEndpoint>();
    public DbSet<ClusterIdentity> Cluster => Set<ClusterIdentity>();
    public DbSet<LoginRequest> LoginRequests => Set<LoginRequest>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<AuditEntry> Audit => Set<AuditEntry>();
    public DbSet<Invite> Invites => Set<Invite>();
    public DbSet<AwgAllocation> AwgAllocations => Set<AwgAllocation>();
    public DbSet<ServerProbe> ServerProbes => Set<ServerProbe>();
    public DbSet<PeerCounter> PeerCounters => Set<PeerCounter>();
    public DbSet<DeviceUsage> DeviceUsage => Set<DeviceUsage>();
    public DbSet<ServerUsage> ServerUsage => Set<ServerUsage>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Account>(e =>
        {
            e.HasIndex(x => x.TelegramId).IsUnique();
            e.HasIndex(x => x.Email).IsUnique();
            e.HasIndex(x => x.LoginEmailNormalized).IsUnique();
            e.Property(x => x.LoginEmailNormalized).HasMaxLength(254);
            e.HasIndex(x => x.AppKey).IsUnique();
            e.Property(x => x.Role).HasMaxLength(16);
            e.HasMany(x => x.Devices).WithOne(x => x.Account!).HasForeignKey(x => x.AccountId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<Device>(e =>
        {
            e.HasIndex(x => x.AwgPublicKey).IsUnique();
            e.HasIndex(x => x.Ip).IsUnique();
            e.HasIndex(x => new { x.AccountId, x.InstallationId });
            e.HasIndex(x => x.SubscriptionTokenHash).IsUnique();
            e.HasIndex(x => x.AppTokenHash).IsUnique();
            e.HasIndex(x => new { x.AccountId, x.StableDeviceHash });
            e.HasIndex(x => x.ExitEndpointId);
            e.Property(x => x.SubscriptionTokenHash).HasMaxLength(64);
            e.Property(x => x.AppTokenHash).HasMaxLength(64);
            e.Property(x => x.StableDeviceHash).HasMaxLength(64);
            e.Property(x => x.PreviousAppTokenHash).HasMaxLength(64);
            e.HasIndex(x => x.PreviousAppTokenHash);
            e.Property(x => x.AutoConnectManaged).HasDefaultValue(false);
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(16);
            e.HasOne<ExitEndpoint>().WithMany().HasForeignKey(x => x.ExitEndpointId).OnDelete(DeleteBehavior.SetNull);
        });
        b.Entity<AwgAllocation>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.AttemptId).HasMaxLength(128);
            e.Property(x => x.AuthKeyHash).HasMaxLength(64);
            e.HasIndex(x => x.AuthKeyHash);
            e.HasIndex(x => new { x.DeviceId, x.AttemptId }).IsUnique();
            e.HasIndex(x => x.DeviceId).IsUnique().HasFilter("\"ReleasedAt\" IS NULL");
            e.HasIndex(x => new { x.ServerId, x.ReleasedAt });
            e.HasOne<Device>().WithMany().HasForeignKey(x => x.DeviceId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Server>().WithMany().HasForeignKey(x => x.ServerId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<ServerProbe>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Kind).HasMaxLength(16);
            e.Property(x => x.Error).HasMaxLength(64);
            e.HasIndex(x => new { x.ServerId, x.At });
            e.HasIndex(x => x.At);
            e.HasOne<Server>().WithMany().HasForeignKey(x => x.ServerId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<PeerCounter>(e =>
        {
            e.HasKey(x => new { x.ServerId, x.PublicKey });
            e.Property(x => x.PublicKey).HasMaxLength(64);
            e.HasOne<Server>().WithMany().HasForeignKey(x => x.ServerId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<DeviceUsage>(e =>
        {
            e.HasKey(x => new { x.DeviceId, x.ServerId, x.Span, x.Bucket });
            e.HasIndex(x => new { x.Span, x.Bucket });
            e.HasIndex(x => new { x.ServerId, x.Span, x.Bucket });
            e.HasOne<Device>().WithMany().HasForeignKey(x => x.DeviceId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Server>().WithMany().HasForeignKey(x => x.ServerId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<ServerUsage>(e =>
        {
            e.HasKey(x => new { x.ServerId, x.Span, x.Bucket });
            e.HasIndex(x => new { x.Span, x.Bucket });
            e.HasOne<Server>().WithMany().HasForeignKey(x => x.ServerId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<Server>(e =>
        {
            e.HasIndex(x => x.AgentTokenHash).IsUnique();
            e.Property(x => x.Role).HasMaxLength(8);
            e.Property(x => x.ProvisioningIdentityHash).HasMaxLength(64);
            e.Property(x => x.AutoSelectEnabled).HasDefaultValue(false);
            e.Property(x => x.NativeCapacity).HasDefaultValue(50);
            e.Property(x => x.ExpectedEgressIpsJson).HasDefaultValue("[]");
        });
        b.Entity<ExitEndpoint>(e =>
        {
            e.HasIndex(x => x.ServerId).IsUnique();
            e.HasOne(x => x.Server).WithMany().HasForeignKey(x => x.ServerId).OnDelete(DeleteBehavior.Cascade);
            e.Property(x => x.Transport).HasMaxLength(16);
            e.Property(x => x.DesiredCredentialsHash).HasMaxLength(64);
        });
        b.Entity<ClusterIdentity>(e =>
        {
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.XrayClientFingerprint).HasMaxLength(32);
        });
        b.Entity<LoginRequest>(e => e.Property(x => x.Id).HasMaxLength(64));
        b.Entity<Invite>(e =>
        {
            e.HasKey(x => x.CodeHash);
            e.HasOne(x => x.Account).WithMany().HasForeignKey(x => x.AccountId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<Session>(e =>
        {
            e.HasKey(x => x.TokenHash);
            e.HasOne(x => x.Account).WithMany().HasForeignKey(x => x.AccountId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
