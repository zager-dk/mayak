using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Mayak.Api.Data.Migrations;

/// <summary>Проверки доступности серверов с API (этап A: ICMP, TCP, TLS). Новая таблица, существующие не меняются.</summary>
[DbContext(typeof(MayakDb))]
[Migration("20261110130000_ServerProbes")]
public sealed class ServerProbes : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.CreateTable(name: "ServerProbes", columns: table => new
        {
            Id = table.Column<long>(type: "bigint", nullable: false)
                .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
            ServerId = table.Column<Guid>(type: "uuid", nullable: false),
            At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
            Kind = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
            Ok = table.Column<bool>(type: "boolean", nullable: false),
            LatencyMs = table.Column<int>(type: "integer", nullable: true),
            Error = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
        }, constraints: table =>
        {
            table.PrimaryKey("PK_ServerProbes", x => x.Id);
            table.ForeignKey("FK_ServerProbes_Servers_ServerId", x => x.ServerId, "Servers", "Id", onDelete: ReferentialAction.Cascade);
        });
        m.CreateIndex(name: "IX_ServerProbes_ServerId_At", table: "ServerProbes", columns: new[] { "ServerId", "At" });
        m.CreateIndex(name: "IX_ServerProbes_At", table: "ServerProbes", column: "At");
    }

    protected override void Down(MigrationBuilder m) => m.DropTable(name: "ServerProbes");
}
