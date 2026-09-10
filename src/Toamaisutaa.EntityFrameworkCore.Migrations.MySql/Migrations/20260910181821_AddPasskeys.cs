using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql.Migrations
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
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserId = table.Column<Guid>(type: "char(36)", nullable: true),
                    TokenHash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Options = table.Column<string>(type: "longtext", nullable: false),
                    Ceremony = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    ConsumedAt = table.Column<long>(type: "bigint", nullable: true)
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
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ToamaisutaaPasskeyCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserId = table.Column<Guid>(type: "char(36)", nullable: false),
                    CredentialId = table.Column<byte[]>(type: "varbinary(256)", maxLength: 256, nullable: false),
                    PublicKey = table.Column<byte[]>(type: "varbinary(1024)", maxLength: 1024, nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    AaGuid = table.Column<Guid>(type: "char(36)", nullable: false),
                    Transports = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true),
                    AttestationFormat = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true),
                    IsBackupEligible = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    IsBackedUp = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Label = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    LastUsedAt = table.Column<long>(type: "bigint", nullable: true)
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
                })
                .Annotation("MySQL:Charset", "utf8mb4");

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
