using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261106120000_DeviceTokens")]
public sealed class DeviceTokens : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<string>(name: "AppTokenHash", table: "Devices", type: "character varying(64)", maxLength: 64, nullable: true);
        m.AddColumn<string>(name: "StableDeviceHash", table: "Devices", type: "character varying(64)", maxLength: 64, nullable: true);
        m.AddColumn<Guid>(name: "LinkAccountId", table: "LoginRequests", type: "uuid", nullable: true);
        m.AddColumn<string>(name: "PreviousAppTokenHash", table: "Devices", type: "character varying(64)", maxLength: 64, nullable: true);
        m.AddColumn<string>(name: "AuthKeyHash", table: "AwgAllocations", type: "character varying(64)", maxLength: 64, nullable: true);
        m.CreateIndex(name: "IX_Devices_PreviousAppTokenHash", table: "Devices", column: "PreviousAppTokenHash");
        m.CreateIndex(name: "IX_AwgAllocations_AuthKeyHash", table: "AwgAllocations", column: "AuthKeyHash");
        m.CreateIndex(name: "IX_Devices_AppTokenHash", table: "Devices", column: "AppTokenHash", unique: true);
        m.CreateIndex(name: "IX_Devices_AccountId_StableDeviceHash", table: "Devices", columns: new[] { "AccountId", "StableDeviceHash" });
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropIndex(name: "IX_AwgAllocations_AuthKeyHash", table: "AwgAllocations");
        m.DropIndex(name: "IX_Devices_PreviousAppTokenHash", table: "Devices");
        m.DropColumn(name: "AuthKeyHash", table: "AwgAllocations");
        m.DropColumn(name: "PreviousAppTokenHash", table: "Devices");
        m.DropIndex(name: "IX_Devices_AccountId_StableDeviceHash", table: "Devices");
        m.DropIndex(name: "IX_Devices_AppTokenHash", table: "Devices");
        m.DropColumn(name: "LinkAccountId", table: "LoginRequests");
        m.DropColumn(name: "StableDeviceHash", table: "Devices");
        m.DropColumn(name: "AppTokenHash", table: "Devices");
    }
}
