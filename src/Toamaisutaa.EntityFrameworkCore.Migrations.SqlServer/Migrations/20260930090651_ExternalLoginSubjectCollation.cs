using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ExternalLoginSubjectCollation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "Subject",
                table: "ToamaisutaaExternalLogins",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: false,
                collation: "Latin1_General_100_BIN2",
                oldClrType: typeof(string),
                oldType: "nvarchar(256)",
                oldMaxLength: 256);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "Subject",
                table: "ToamaisutaaExternalLogins",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(256)",
                oldMaxLength: 256,
                oldCollation: "Latin1_General_100_BIN2");
        }
    }
}
