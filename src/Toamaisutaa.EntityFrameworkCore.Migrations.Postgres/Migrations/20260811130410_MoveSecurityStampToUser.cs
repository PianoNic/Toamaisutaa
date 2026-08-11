using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres.Migrations
{
    /// <summary>
    /// Moves the security stamp from the password credential to the user, and gives the refresh
    /// token the two columns that let a rotation know what the session proved and when.
    /// </summary>
    /// <remarks>
    /// Hand-edited. The scaffolded version dropped the old column first and lost every stamp; the
    /// order here is add, copy, then drop. The same care as the timestamp conversion, for the same
    /// reason: a generated migration knows the shape of the change and nothing about the data.
    /// </remarks>
    public partial class MoveSecurityStampToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaUsers",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationMethods",
                table: "ToamaisutaaRefreshTokens",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaRefreshTokens",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql(
                """
                UPDATE "ToamaisutaaUsers" AS u
                SET "SecurityStamp" = c."SecurityStamp"
                FROM "ToamaisutaaPasswordCredentials" AS c
                WHERE c."UserId" = u."Id";
                """);

            // A user provisioned from an identity provider never had one. An empty stamp would
            // compare equal to the empty default on a token, so every such account gets a real
            // value rather than a placeholder that silently matches.
            migrationBuilder.Sql(
                """
                UPDATE "ToamaisutaaUsers"
                SET "SecurityStamp" = md5(random()::text || clock_timestamp()::text)
                WHERE "SecurityStamp" = '';
                """);

            // Live sessions keep working across the upgrade. Nothing about those credentials
            // changed, so signing everyone out would be a cost with no security behind it.
            migrationBuilder.Sql(
                """
                UPDATE "ToamaisutaaRefreshTokens" AS t
                SET "SecurityStamp" = u."SecurityStamp", "AuthenticationMethods" = 'pwd'
                FROM "ToamaisutaaUsers" AS u
                WHERE u."Id" = t."UserId";
                """);

            migrationBuilder.DropColumn(
                name: "SecurityStamp",
                table: "ToamaisutaaPasswordCredentials");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaPasswordCredentials",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql(
                """
                UPDATE "ToamaisutaaPasswordCredentials" AS c
                SET "SecurityStamp" = u."SecurityStamp"
                FROM "ToamaisutaaUsers" AS u
                WHERE u."Id" = c."UserId";
                """);

            migrationBuilder.DropColumn(
                name: "SecurityStamp",
                table: "ToamaisutaaUsers");

            migrationBuilder.DropColumn(
                name: "AuthenticationMethods",
                table: "ToamaisutaaRefreshTokens");

            migrationBuilder.DropColumn(
                name: "SecurityStamp",
                table: "ToamaisutaaRefreshTokens");
        }
    }
}
