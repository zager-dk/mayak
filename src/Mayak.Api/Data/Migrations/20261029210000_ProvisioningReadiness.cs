using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261029210000_ProvisioningReadiness")]
public sealed class ProvisioningReadiness : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<string>("ProvisioningIdentityHash", "Servers", type: "character varying(64)", maxLength: 64, nullable: true);
        m.AddColumn<long>("ProvisioningConfirmedRevision", "Servers", type: "bigint", nullable: true);
        m.AddColumn<DateTime>("ProvisioningConfirmedAt", "Servers", type: "timestamp with time zone", nullable: true);
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropColumn("ProvisioningIdentityHash", "Servers");
        m.DropColumn("ProvisioningConfirmedRevision", "Servers");
        m.DropColumn("ProvisioningConfirmedAt", "Servers");
    }
}
