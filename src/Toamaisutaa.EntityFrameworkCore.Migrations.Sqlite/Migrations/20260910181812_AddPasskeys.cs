using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddPasskeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ToamaisutaaPasskeyChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Options = table.Column<string>(type: "TEXT", nullable: false),
                    Ceremony = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    ExpiresAt = table.Column<long>(type: "INTEGER", nullable: false),
                    ConsumedAt = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaPasskeyChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaPasskeyChallenges_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ToamaisutaaPasskeyCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CredentialId = table.Column<byte[]>(type: "BLOB", maxLength: 256, nullable: false),
                    PublicKey = table.Column<byte[]>(type: "BLOB", maxLength: 1024, nullable: false),
                    SignCount = table.Column<long>(type: "INTEGER", nullable: false),
                    AaGuid = table.Column<Guid>(type: "TEXT", nullable: false),
                    Transports = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    AttestationFormat = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    IsBackupEligible = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsBackedUp = table.Column<bool>(type: "INTEGER", nullable: false),
                    Label = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    LastUsedAt = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaPasskeyCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaPasskeyCredentials_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaPasskeyChallenges_TokenHash",
                table: "ToamaisutaaPasskeyChallenges",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaPasskeyChallenges_UserId",
                table: "ToamaisutaaPasskeyChallenges",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaPasskeyCredentials_CredentialId",
                table: "ToamaisutaaPasskeyCredentials",
                column: "CredentialId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaPasskeyCredentials_UserId",
                table: "ToamaisutaaPasskeyCredentials",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ToamaisutaaPasskeyChallenges");

            migrationBuilder.DropTable(
                name: "ToamaisutaaPasskeyCredentials");
        }
    }
}
