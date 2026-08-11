using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class AddTrustedDevices : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "SecondFactorAt",
                table: "ToamaisutaaRefreshTokens",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TwoFactorSource",
                table: "ToamaisutaaRefreshTokens",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "ToamaisutaaTrustedDevices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FamilyId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SecurityStamp = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SecondFactorAt = table.Column<long>(type: "bigint", nullable: false),
                    Label = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    IpAddress = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    FamilyStartedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    LastUsedAt = table.Column<long>(type: "bigint", nullable: false),
                    RotatedAt = table.Column<long>(type: "bigint", nullable: true),
                    RevokedAt = table.Column<long>(type: "bigint", nullable: true),
                    RevokedReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaTrustedDevices", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaTrustedDevices_ToamaisutaaUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaTrustedDevices_FamilyId",
                table: "ToamaisutaaTrustedDevices",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaTrustedDevices_TokenHash",
                table: "ToamaisutaaTrustedDevices",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaTrustedDevices_UserId",
                table: "ToamaisutaaTrustedDevices",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ToamaisutaaTrustedDevices");

            migrationBuilder.DropColumn(
                name: "SecondFactorAt",
                table: "ToamaisutaaRefreshTokens");

            migrationBuilder.DropColumn(
                name: "TwoFactorSource",
                table: "ToamaisutaaRefreshTokens");
        }
    }
}
