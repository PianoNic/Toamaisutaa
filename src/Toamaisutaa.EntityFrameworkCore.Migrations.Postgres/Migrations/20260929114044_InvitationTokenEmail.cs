using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class InvitationTokenEmail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Email",
                table: "ToamaisutaaInvitationTokens",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NormalizedEmail",
                table: "ToamaisutaaInvitationTokens",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaInvitationTokens_NormalizedEmail",
                table: "ToamaisutaaInvitationTokens",
                column: "NormalizedEmail");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ToamaisutaaInvitationTokens_NormalizedEmail",
                table: "ToamaisutaaInvitationTokens");

            migrationBuilder.DropColumn(
                name: "Email",
                table: "ToamaisutaaInvitationTokens");

            migrationBuilder.DropColumn(
                name: "NormalizedEmail",
                table: "ToamaisutaaInvitationTokens");
        }
    }
}
