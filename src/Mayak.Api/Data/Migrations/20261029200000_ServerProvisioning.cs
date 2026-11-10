using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261029200000_ServerProvisioning")]
public sealed class ServerProvisioning : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<string>("ProvisioningStatus", "Servers", type: "text", nullable: true);
        m.AddColumn<string>("ProvisioningMessage", "Servers", type: "text", nullable: true);
        m.AddColumn<DateTime>("ProvisioningUpdatedAt", "Servers", type: "timestamp with time zone", nullable: true);
        m.AddColumn<string>("TrustedHostFingerprint", "Servers", type: "text", nullable: true);
        m.AddColumn<bool>("ProvisionIdentityMatched", "Servers", type: "boolean", nullable: false, defaultValue: false);
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropColumn("ProvisioningStatus", "Servers");
        m.DropColumn("ProvisioningMessage", "Servers");
        m.DropColumn("ProvisioningUpdatedAt", "Servers");
        m.DropColumn("TrustedHostFingerprint", "Servers");
        m.DropColumn("ProvisionIdentityMatched", "Servers");
    }
}
