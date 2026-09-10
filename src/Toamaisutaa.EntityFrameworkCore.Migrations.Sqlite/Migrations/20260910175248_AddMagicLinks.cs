using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddMagicLinks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AuthenticationMethods",
                table: "ToamaisutaaTwoFactorChallenges",
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "ToamaisutaaMagicLinkTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAt = table.Column<long>(type: "INTEGER", nullable: false),
                    ConsumedAt = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaMagicLinkTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaMagicLinkTokens_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaMagicLinkTokens_TokenHash",
                table: "ToamaisutaaMagicLinkTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaMagicLinkTokens_UserId",
                table: "ToamaisutaaMagicLinkTokens",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ToamaisutaaMagicLinkTokens");

            migrationBuilder.DropColumn(
                name: "AuthenticationMethods",
                table: "ToamaisutaaTwoFactorChallenges");
        }
    }
}
