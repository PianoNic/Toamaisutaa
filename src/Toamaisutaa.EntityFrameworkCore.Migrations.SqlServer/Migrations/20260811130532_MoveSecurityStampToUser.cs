using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer.Migrations
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
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AuthenticationMethods",
                table: "ToamaisutaaRefreshTokens",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "SecurityStamp",
                table: "ToamaisutaaRefreshTokens",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql(
                """
                UPDATE u
                SET u.[SecurityStamp] = c.[SecurityStamp]
                FROM [ToamaisutaaUsers] AS u
                INNER JOIN [ToamaisutaaPasswordCredentials] AS c ON c.[UserId] = u.[Id];
                """);

            // A user provisioned from an identity provider never had one. An empty stamp would
            // compare equal to the empty default on a token, so every such account gets a real
            // value rather than a placeholder that silently matches.
            migrationBuilder.Sql(
                """
                UPDATE [ToamaisutaaUsers]
                SET [SecurityStamp] = CONVERT(nvarchar(36), NEWID())
                WHERE [SecurityStamp] = N'';
                """);

            // Live sessions keep working across the upgrade. Nothing about those credentials
            // changed, so signing everyone out would be a cost with no security behind it.
            migrationBuilder.Sql(
                """
                UPDATE t
                SET t.[SecurityStamp] = u.[SecurityStamp], t.[AuthenticationMethods] = N'pwd'
                FROM [ToamaisutaaRefreshTokens] AS t
                INNER JOIN [ToamaisutaaUsers] AS u ON u.[Id] = t.[UserId];
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
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql(
                """
                UPDATE c
                SET c.[SecurityStamp] = u.[SecurityStamp]
                FROM [ToamaisutaaPasswordCredentials] AS c
                INNER JOIN [ToamaisutaaUsers] AS u ON u.[Id] = c.[UserId];
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
