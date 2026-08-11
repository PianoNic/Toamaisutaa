using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql.Migrations
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
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserId = table.Column<Guid>(type: "char(36)", nullable: false),
                    CodeHash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ConsumedAt = table.Column<long>(type: "bigint", nullable: true)
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
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ToamaisutaaTwoFactorChallenges",
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
                    table.PrimaryKey("PK_ToamaisutaaTwoFactorChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaTwoFactorChallenges_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ToamaisutaaUserTwoFactors",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "char(36)", nullable: false),
                    SecretCiphertext = table.Column<byte[]>(type: "varbinary(256)", maxLength: 256, nullable: false),
                    SecretNonce = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    SecretTag = table.Column<byte[]>(type: "varbinary(32)", maxLength: 32, nullable: false),
                    EncryptionKeyVersion = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    ConfirmedAt = table.Column<long>(type: "bigint", nullable: true),
                    LastUsedStep = table.Column<long>(type: "bigint", nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<long>(type: "bigint", nullable: false)
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
                })
                .Annotation("MySQL:Charset", "utf8mb4");

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
