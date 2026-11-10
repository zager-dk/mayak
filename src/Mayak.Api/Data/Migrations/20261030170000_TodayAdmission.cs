using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261030170000_TodayAdmission")]
public sealed class TodayAdmission : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<bool>(name: "AutoConnectManaged", table: "Devices", type: "boolean", nullable: false, defaultValue: false);
        m.AddColumn<bool>(name: "AutoSelectEnabled", table: "Servers", type: "boolean", nullable: false, defaultValue: false);
        m.AddColumn<int>(name: "NativeCapacity", table: "Servers", type: "integer", nullable: false, defaultValue: 50);
        m.AddColumn<string>(name: "ExpectedEgressIpsJson", table: "Servers", type: "text", nullable: false, defaultValue: "[]");
        m.CreateTable(name: "AwgAllocations", columns: table => new
        {
            Id = table.Column<Guid>(type: "uuid", nullable: false),
            DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
            ServerId = table.Column<Guid>(type: "uuid", nullable: false),
            AttemptId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
            CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
            ProvenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
            ReleasedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
        }, constraints: table =>
        {
            table.PrimaryKey("PK_AwgAllocations", x => x.Id);
            table.ForeignKey("FK_AwgAllocations_Devices_DeviceId", x => x.DeviceId, "Devices", "Id", onDelete: ReferentialAction.Cascade);
            table.ForeignKey("FK_AwgAllocations_Servers_ServerId", x => x.ServerId, "Servers", "Id", onDelete: ReferentialAction.Cascade);
        });
        m.CreateIndex(name: "IX_AwgAllocations_DeviceId_AttemptId", table: "AwgAllocations", columns: new[] { "DeviceId", "AttemptId" }, unique: true);
        m.CreateIndex(name: "IX_AwgAllocations_DeviceId", table: "AwgAllocations", column: "DeviceId", unique: true, filter: "\"ReleasedAt\" IS NULL");
        m.CreateIndex(name: "IX_AwgAllocations_ServerId_ReleasedAt", table: "AwgAllocations", columns: new[] { "ServerId", "ReleasedAt" });
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropTable("AwgAllocations");
        m.DropColumn("AutoConnectManaged", "Devices");
        m.DropColumn("AutoSelectEnabled", "Servers");
        m.DropColumn("NativeCapacity", "Servers");
        m.DropColumn("ExpectedEgressIpsJson", "Servers");
    }
}
