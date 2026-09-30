using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    /// <remarks>
    /// Written as SQL rather than generated. MySql.EntityFrameworkCore leaves the collation out of the
    /// MODIFY it generates for AlterColumn, so the generated migration applied cleanly, was recorded
    /// as applied, and changed nothing - found by running it against a real server.
    /// </remarks>
    public partial class ExternalLoginSubjectCollation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                "ALTER TABLE `ToamaisutaaExternalLogins` MODIFY `Subject` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                "ALTER TABLE `ToamaisutaaExternalLogins` MODIFY `Subject` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL;");
        }
    }
}
