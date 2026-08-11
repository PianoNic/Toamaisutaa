using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql.Migrations
{
    /// <summary>
    /// Moves the security stamp from the password credential to the user, and gives the refresh
    /// token the two columns that let a rotation know what the session proved and when.
    /// </summary>
    /// <remarks>
    /// Hand-edited. The scaffolded version dropped the old column first and lost every stamp; the
    /// order here is add, copy, then drop.
    /// </remarks>
    public partial class MoveSecurityStampToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaUsers",
                type: "varchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationMethods",
                table: "ToamaisutaaRefreshTokens",
                type: "varchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaRefreshTokens",
                type: "varchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql(
                """
                UPDATE `ToamaisutaaUsers` AS u
                INNER JOIN `ToamaisutaaPasswordCredentials` AS c ON c.`UserId` = u.`Id`
                SET u.`SecurityStamp` = c.`SecurityStamp`;
                """);

            // A user provisioned from an identity provider never had one. An empty stamp would
            // compare equal to the empty default on a token, so every such account gets a real
            // value rather than a placeholder that silently matches.
            migrationBuilder.Sql(
                """
                UPDATE `ToamaisutaaUsers`
                SET `SecurityStamp` = REPLACE(UUID(), '-', '')
                WHERE `SecurityStamp` = '';
                """);

            // Live sessions keep working across the upgrade. Nothing about those credentials
            // changed, so signing everyone out would be a cost with no security behind it.
            migrationBuilder.Sql(
                """
                UPDATE `ToamaisutaaRefreshTokens` AS t
                INNER JOIN `ToamaisutaaUsers` AS u ON u.`Id` = t.`UserId`
                SET t.`SecurityStamp` = u.`SecurityStamp`, t.`AuthenticationMethods` = 'pwd';
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
                type: "varchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql(
                """
                UPDATE `ToamaisutaaPasswordCredentials` AS c
                INNER JOIN `ToamaisutaaUsers` AS u ON u.`Id` = c.`UserId`
                SET c.`SecurityStamp` = u.`SecurityStamp`;
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
