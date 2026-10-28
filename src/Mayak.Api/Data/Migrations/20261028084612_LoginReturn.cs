using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Mayak.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class LoginReturn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ReturnPath",
                table: "LoginRequests",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Uses",
                table: "LoginRequests",
                type: "integer",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ReturnPath",
                table: "LoginRequests");

            migrationBuilder.DropColumn(
                name: "Uses",
                table: "LoginRequests");
        }
    }
}
