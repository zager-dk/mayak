using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261028210000_VlessPool")]
public sealed class VlessPool : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<string>("ServiceProtocol", "Devices", type: "text", nullable: true);
        m.AddColumn<Guid>("ExitEndpointId", "Devices", type: "uuid", nullable: true);
        m.AddColumn<long>("CredentialsRevision", "Devices", type: "bigint", nullable: false, defaultValue: 0L);
        m.CreateTable("ExitEndpoints", t => new
        {
            Id = t.Column<Guid>(type: "uuid", nullable: false), ServerId = t.Column<Guid>(type: "uuid", nullable: false),
            Host = t.Column<string>(type: "text", nullable: false), Port = t.Column<int>(type: "integer", nullable: false),
            PublicKey = t.Column<string>(type: "text", nullable: false), Sni = t.Column<string>(type: "text", nullable: false),
            ShortId = t.Column<string>(type: "text", nullable: false), Flow = t.Column<string>(type: "text", nullable: false),
            Transport = t.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
            Fingerprint = t.Column<string>(type: "text", nullable: false, defaultValue: "chrome"),
            XhttpPath = t.Column<string>(type: "text", nullable: false, defaultValue: "/"),
            XhttpHost = t.Column<string>(type: "text", nullable: false, defaultValue: ""),
            XhttpMode = t.Column<string>(type: "text", nullable: false, defaultValue: "auto"),
            IdentityVersion = t.Column<long>(type: "bigint", nullable: false), AllowNewConnections = t.Column<bool>(type: "boolean", nullable: false),
            CapacitySlots = t.Column<int>(type: "integer", nullable: false), AppliedCredentialsRevision = t.Column<long>(type: "bigint", nullable: false),
            ProtocolReportReceivedAt = t.Column<DateTime>(type: "timestamp with time zone", nullable: true),
            ReportedIdentityVersion = t.Column<long>(type: "bigint", nullable: false), ReportedCredentialsRevision = t.Column<long>(type: "bigint", nullable: false),
            RuntimeReady = t.Column<bool>(type: "boolean", nullable: false), ConfigValid = t.Column<bool>(type: "boolean", nullable: false),
            SelfTestPassed = t.Column<bool>(type: "boolean", nullable: false), DryRun = t.Column<bool>(type: "boolean", nullable: false),
            ProtocolError = t.Column<string>(type: "text", nullable: true), OccupiedSlots = t.Column<int>(type: "integer", nullable: false)
        }, constraints: t => { t.PrimaryKey("PK_ExitEndpoints", x => x.Id); t.ForeignKey("FK_ExitEndpoints_Servers_ServerId", x => x.ServerId, "Servers", "Id", onDelete: ReferentialAction.Cascade); });
        m.CreateIndex("IX_ExitEndpoints_ServerId", "ExitEndpoints", "ServerId", unique: true);
        m.CreateIndex("IX_Devices_ExitEndpointId", "Devices", "ExitEndpointId");
        m.AddForeignKey("FK_Devices_ExitEndpoints_ExitEndpointId", "Devices", "ExitEndpointId", "ExitEndpoints", principalColumn: "Id", onDelete: ReferentialAction.SetNull);
    }
    protected override void Down(MigrationBuilder m)
    {
        m.DropForeignKey("FK_Devices_ExitEndpoints_ExitEndpointId", "Devices");
        m.DropTable("ExitEndpoints"); m.DropIndex("IX_Devices_ExitEndpointId", "Devices");
        m.DropColumn("ServiceProtocol", "Devices"); m.DropColumn("ExitEndpointId", "Devices"); m.DropColumn("CredentialsRevision", "Devices");
    }
}
