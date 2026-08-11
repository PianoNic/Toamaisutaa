using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddTwoFactor : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ToamaisutaaRecoveryCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CodeHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    ConsumedAt = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaRecoveryCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaRecoveryCodes_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ToamaisutaaTwoFactorChallenges",
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
                    table.PrimaryKey("PK_ToamaisutaaTwoFactorChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaTwoFactorChallenges_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ToamaisutaaUserTwoFactors",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    SecretCiphertext = table.Column<byte[]>(type: "BLOB", maxLength: 256, nullable: false),
                    SecretNonce = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    SecretTag = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    EncryptionKeyVersion = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ConfirmedAt = table.Column<long>(type: "INTEGER", nullable: true),
                    LastUsedStep = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedAt = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedAt = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaUserTwoFactors", x => x.UserId);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaUserTwoFactors_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaRecoveryCodes_UserId_CodeHash",
                table: "ToamaisutaaRecoveryCodes",
                columns: new[] { "UserId", "CodeHash" });

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaTwoFactorChallenges_TokenHash",
                table: "ToamaisutaaTwoFactorChallenges",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaTwoFactorChallenges_UserId",
                table: "ToamaisutaaTwoFactorChallenges",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ToamaisutaaRecoveryCodes");

            migrationBuilder.DropTable(
                name: "ToamaisutaaTwoFactorChallenges");

            migrationBuilder.DropTable(
                name: "ToamaisutaaUserTwoFactors");
        }
    }
}
