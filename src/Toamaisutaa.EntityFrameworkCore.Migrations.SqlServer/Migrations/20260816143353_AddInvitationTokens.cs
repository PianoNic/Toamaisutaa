using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddInvitationTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ToamaisutaaInvitationTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    ConsumedAt = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaInvitationTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaInvitationTokens_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaInvitationTokens_TokenHash",
                table: "ToamaisutaaInvitationTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaInvitationTokens_UserId",
                table: "ToamaisutaaInvitationTokens",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ToamaisutaaInvitationTokens");
        }
    }
}
