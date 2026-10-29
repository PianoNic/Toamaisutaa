using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class EmailVerificationCodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ToamaisutaaEmailVerificationChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserId = table.Column<Guid>(type: "char(36)", nullable: false),
                    TokenHash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    NormalizedEmail = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false),
                    SecurityStamp = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    ConsumedAt = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaEmailVerificationChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaEmailVerificationChallenges_ToamaisutaaUsers_User~",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ToamaisutaaEmailVerificationCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserId = table.Column<Guid>(type: "char(36)", nullable: false),
                    NormalizedEmail = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: false),
                    CodeHash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    FailedAttempts = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    ConsumedAt = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaEmailVerificationCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaEmailVerificationCodes_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaEmailVerificationChallenges_TokenHash",
                table: "ToamaisutaaEmailVerificationChallenges",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaEmailVerificationChallenges_UserId",
                table: "ToamaisutaaEmailVerificationChallenges",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaEmailVerificationCodes_UserId",
                table: "ToamaisutaaEmailVerificationCodes",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ToamaisutaaEmailVerificationChallenges");

            migrationBuilder.DropTable(
                name: "ToamaisutaaEmailVerificationCodes");
        }
    }
}
