using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql.Migrations
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
                type: "varchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "ToamaisutaaMagicLinkTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserId = table.Column<Guid>(type: "char(36)", nullable: false),
                    TokenHash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    ConsumedAt = table.Column<long>(type: "bigint", nullable: true)
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
                })
                .Annotation("MySQL:Charset", "utf8mb4");

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
