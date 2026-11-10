using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

/// <summary>Отпечаток uTLS для клиентов отдельно от identity выхода. Пусто — прежнее поведение (отпечаток из XrayJson).</summary>
[DbContext(typeof(MayakDb))]
[Migration("20261110120000_XrayClientFingerprint")]
public sealed class XrayClientFingerprint : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<string>(name: "XrayClientFingerprint", table: "Cluster", type: "character varying(32)", maxLength: 32, nullable: true);
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropColumn(name: "XrayClientFingerprint", table: "Cluster");
    }
}
