using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

/// <summary>
/// История использования для статистики админки: счётчики пиров, объём и время в сети по устройствам и серверам.
/// Только новые таблицы; существующие не меняются. Адресов пользователей и сайтов здесь нет.
/// </summary>
[DbContext(typeof(MayakDb))]
[Migration("20261113120000_UsageHistory")]
public sealed class UsageHistory : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.CreateTable(name: "PeerCounters", columns: t => new
        {
            ServerId = t.Column<Guid>(type: "uuid", nullable: false),
            PublicKey = t.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
            RxBytes = t.Column<long>(type: "bigint", nullable: false),
            TxBytes = t.Column<long>(type: "bigint", nullable: false),
            LastHandshake = t.Column<DateTime>(type: "timestamp with time zone", nullable: true),
            At = t.Column<DateTime>(type: "timestamp with time zone", nullable: false)
        }, constraints: t =>
        {
            t.PrimaryKey("PK_PeerCounters", x => new { x.ServerId, x.PublicKey });
            t.ForeignKey("FK_PeerCounters_Servers_ServerId", x => x.ServerId, "Servers", "Id", onDelete: ReferentialAction.Cascade);
        });

        m.CreateTable(name: "DeviceUsage", columns: t => new
        {
            DeviceId = t.Column<Guid>(type: "uuid", nullable: false),
            ServerId = t.Column<Guid>(type: "uuid", nullable: false),
            Span = t.Column<short>(type: "smallint", nullable: false),
            Bucket = t.Column<DateTime>(type: "timestamp with time zone", nullable: false),
            RxBytes = t.Column<long>(type: "bigint", nullable: false),
            TxBytes = t.Column<long>(type: "bigint", nullable: false),
            OnlineSeconds = t.Column<int>(type: "integer", nullable: false)
        }, constraints: t =>
        {
            t.PrimaryKey("PK_DeviceUsage", x => new { x.DeviceId, x.ServerId, x.Span, x.Bucket });
            t.ForeignKey("FK_DeviceUsage_Devices_DeviceId", x => x.DeviceId, "Devices", "Id", onDelete: ReferentialAction.Cascade);
            t.ForeignKey("FK_DeviceUsage_Servers_ServerId", x => x.ServerId, "Servers", "Id", onDelete: ReferentialAction.Cascade);
        });
        m.CreateIndex(name: "IX_DeviceUsage_Span_Bucket", table: "DeviceUsage", columns: new[] { "Span", "Bucket" });
        m.CreateIndex(name: "IX_DeviceUsage_ServerId_Span_Bucket", table: "DeviceUsage", columns: new[] { "ServerId", "Span", "Bucket" });

        m.CreateTable(name: "ServerUsage", columns: t => new
        {
            ServerId = t.Column<Guid>(type: "uuid", nullable: false),
            Span = t.Column<short>(type: "smallint", nullable: false),
            Bucket = t.Column<DateTime>(type: "timestamp with time zone", nullable: false),
            RxBytes = t.Column<long>(type: "bigint", nullable: false),
            TxBytes = t.Column<long>(type: "bigint", nullable: false),
            PeakPeers = t.Column<int>(type: "integer", nullable: false),
            PeerSeconds = t.Column<long>(type: "bigint", nullable: false),
            Reports = t.Column<int>(type: "integer", nullable: false)
        }, constraints: t =>
        {
            t.PrimaryKey("PK_ServerUsage", x => new { x.ServerId, x.Span, x.Bucket });
            t.ForeignKey("FK_ServerUsage_Servers_ServerId", x => x.ServerId, "Servers", "Id", onDelete: ReferentialAction.Cascade);
        });
        m.CreateIndex(name: "IX_ServerUsage_Span_Bucket", table: "ServerUsage", columns: new[] { "Span", "Bucket" });
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropTable(name: "DeviceUsage");
        m.DropTable(name: "ServerUsage");
        m.DropTable(name: "PeerCounters");
    }
}
