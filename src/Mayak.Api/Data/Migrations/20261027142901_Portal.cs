using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class Portal : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Devices_AccountId",
                table: "Devices");

            migrationBuilder.AddColumn<string>(
                name: "AppVersion",
                table: "Devices",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ConfigFetchedAt",
                table: "Devices",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OsVersion",
                table: "Devices",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AppKey",
                table: "Accounts",
                type: "text",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Devices_AccountId_InstallationId",
                table: "Devices",
                columns: new[] { "AccountId", "InstallationId" });

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_AppKey",
                table: "Accounts",
                column: "AppKey",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Devices_AccountId_InstallationId",
                table: "Devices");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_AppKey",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "AppVersion",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "ConfigFetchedAt",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "OsVersion",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "AppKey",
                table: "Accounts");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_AccountId",
                table: "Devices",
                column: "AccountId");
        }
    }
}
