using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class ExternalLoginRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ToamaisutaaExternalLoginRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderKey = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    StateHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Nonce = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CodeVerifier = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    RedirectUri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    ReturnUrl = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    ClientState = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    ClientCodeChallenge = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    LinkUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAt = table.Column<long>(type: "bigint", nullable: false),
                    ConsumedAt = table.Column<long>(type: "bigint", nullable: true),
                    ExchangeCodeHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    ExchangeConsumedAt = table.Column<long>(type: "bigint", nullable: true),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    SecurityStamp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ToamaisutaaExternalLoginRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ToamaisutaaExternalLoginRequests_ToamaisutaaUsers_LinkUserId",
                        column: x => x.LinkUserId,
                        principalTable: "ToamaisutaaUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaExternalLoginRequests_ExchangeCodeHash",
                table: "ToamaisutaaExternalLoginRequests",
                column: "ExchangeCodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaExternalLoginRequests_ExpiresAt",
                table: "ToamaisutaaExternalLoginRequests",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaExternalLoginRequests_LinkUserId",
                table: "ToamaisutaaExternalLoginRequests",
                column: "LinkUserId");

            migrationBuilder.CreateIndex(
                name: "IX_ToamaisutaaExternalLoginRequests_StateHash",
                table: "ToamaisutaaExternalLoginRequests",
                column: "StateHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ToamaisutaaExternalLoginRequests");
        }
    }
}
