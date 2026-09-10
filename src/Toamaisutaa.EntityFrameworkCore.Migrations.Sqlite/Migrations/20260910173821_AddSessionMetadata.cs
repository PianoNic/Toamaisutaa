using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionMetadata : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "IpAddress",
                table: "ToamaisutaaRefreshTokens",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "LastUsedAt",
                table: "ToamaisutaaRefreshTokens",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "UserAgent",
                table: "ToamaisutaaRefreshTokens",
                type: "TEXT",
                maxLength: 256,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IpAddress",
                table: "ToamaisutaaRefreshTokens");

            migrationBuilder.DropColumn(
                name: "LastUsedAt",
                table: "ToamaisutaaRefreshTokens");

            migrationBuilder.DropColumn(
                name: "UserAgent",
                table: "ToamaisutaaRefreshTokens");
        }
    }
}
