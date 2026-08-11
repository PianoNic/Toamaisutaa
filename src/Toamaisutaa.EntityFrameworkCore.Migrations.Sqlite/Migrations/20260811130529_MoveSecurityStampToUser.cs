using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <summary>
    /// Moves the security stamp from the password credential to the user, and gives the refresh
    /// token the two columns that let a rotation know what the session proved and when.
    /// </summary>
    /// <remarks>
    /// Hand-edited. The scaffolded version dropped the old column first and lost every stamp; the
    /// order here is add, copy, then drop. SQLite has no UPDATE ... FROM before 3.33, so the copy
    /// is a correlated subquery, which works on every version.
    /// <para>
    /// Applying this logs "the migration operation 'PRAGMA foreign_keys = 0;' cannot be executed in
    /// a transaction". That is inherent to dropping a column on SQLite - the provider implements it
    /// as a table rebuild, which cannot be transactional - and not a fault in this migration.
    /// Nothing to investigate.
    /// </para>
    /// <para>
    /// The warning's advice still applies: an interruption leaves this partially applied and needs
    /// reverting by hand before a retry, because the three AddColumn calls would run a second time.
    /// What it does not risk is data. The drop is last, so any interruption leaves the source column
    /// still populated and the stamps recoverable.
    /// </para>
    /// </remarks>
    public partial class MoveSecurityStampToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaUsers",
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationMethods",
                table: "ToamaisutaaRefreshTokens",
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaRefreshTokens",
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            // A user provisioned from an identity provider never had a stamp. The COALESCE gives
            // those rows a real value rather than the empty default, which would compare equal to
            // the empty default on a token.
            migrationBuilder.Sql(
                """
                UPDATE "ToamaisutaaUsers"
                SET "SecurityStamp" = COALESCE(
                    (SELECT c."SecurityStamp"
                     FROM "ToamaisutaaPasswordCredentials" AS c
                     WHERE c."UserId" = "ToamaisutaaUsers"."Id"),
                    lower(hex(randomblob(16))));
                """);

            // Live sessions keep working across the upgrade. Nothing about those credentials
            // changed, so signing everyone out would be a cost with no security behind it.
            migrationBuilder.Sql(
                """
                UPDATE "ToamaisutaaRefreshTokens"
                SET "SecurityStamp" = COALESCE(
                        (SELECT u."SecurityStamp"
                         FROM "ToamaisutaaUsers" AS u
                         WHERE u."Id" = "ToamaisutaaRefreshTokens"."UserId"),
                        ''),
                    "AuthenticationMethods" = 'pwd';
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
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql(
                """
                UPDATE "ToamaisutaaPasswordCredentials"
                SET "SecurityStamp" = COALESCE(
                    (SELECT u."SecurityStamp"
                     FROM "ToamaisutaaUsers" AS u
                     WHERE u."Id" = "ToamaisutaaPasswordCredentials"."UserId"),
                    '');
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
