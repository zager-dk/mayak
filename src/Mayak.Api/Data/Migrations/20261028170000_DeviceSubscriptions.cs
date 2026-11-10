using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261028170000_DeviceSubscriptions")]
public sealed class DeviceSubscriptions : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "SubscriptionTokenHash", table: "Devices", type: "character varying(64)", maxLength: 64, nullable: true);
        migrationBuilder.CreateIndex(
            name: "IX_Devices_SubscriptionTokenHash", table: "Devices", column: "SubscriptionTokenHash", unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(name: "IX_Devices_SubscriptionTokenHash", table: "Devices");
        migrationBuilder.DropColumn(name: "SubscriptionTokenHash", table: "Devices");
    }
}
