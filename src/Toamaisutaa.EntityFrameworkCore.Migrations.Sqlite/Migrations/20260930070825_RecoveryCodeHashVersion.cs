using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class RecoveryCodeHashVersion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "HashVersion",
                table: "ToamaisutaaRecoveryCodes",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HashVersion",
                table: "ToamaisutaaRecoveryCodes");
        }
    }
}
