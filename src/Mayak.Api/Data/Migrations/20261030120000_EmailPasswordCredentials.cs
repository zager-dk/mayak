using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations;

[DbContext(typeof(MayakDb))]
[Migration("20261030120000_EmailPasswordCredentials")]
public sealed class EmailPasswordCredentials : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.AddColumn<string>(name: "LoginEmailNormalized", table: "Accounts", type: "character varying(254)", maxLength: 254, nullable: true);
        m.AddColumn<string>(name: "PasswordHash", table: "Accounts", type: "text", nullable: true);
        m.CreateIndex(name: "IX_Accounts_LoginEmailNormalized", table: "Accounts", column: "LoginEmailNormalized", unique: true);
    }

    // Данные аутентификации не удаляются автоматическим rollback.
    protected override void Down(MigrationBuilder m) { }
}
