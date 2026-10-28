using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class LockoutStrikes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "LockoutStrikes",
                table: "ToamaisutaaUserTwoFactors",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "LockoutStrikes",
                table: "ToamaisutaaPasswordCredentials",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LockoutStrikes",
                table: "ToamaisutaaUserTwoFactors");

            migrationBuilder.DropColumn(
                name: "LockoutStrikes",
                table: "ToamaisutaaPasswordCredentials");
        }
    }
}
