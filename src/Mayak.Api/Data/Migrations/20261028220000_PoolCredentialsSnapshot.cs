using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261028220000_PoolCredentialsSnapshot")]
public sealed class PoolCredentialsSnapshot : Migration
{
    protected override void Up(MigrationBuilder m) => m.AddColumn<string>(
        "DesiredCredentialsHash", "ExitEndpoints", type: "character varying(64)", maxLength: 64,
        nullable: false, defaultValue: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945");

    protected override void Down(MigrationBuilder m) => m.DropColumn("DesiredCredentialsHash", "ExitEndpoints");
}
