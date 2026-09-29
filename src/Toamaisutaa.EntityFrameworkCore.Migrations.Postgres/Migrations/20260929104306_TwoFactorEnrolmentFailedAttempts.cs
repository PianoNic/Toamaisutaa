using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class TwoFactorEnrolmentFailedAttempts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "FailedAttemptCount",
                table: "ToamaisutaaUserTwoFactors",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<long>(
                name: "FirstFailedAttemptAt",
                table: "ToamaisutaaUserTwoFactors",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "LockedOutUntil",
                table: "ToamaisutaaUserTwoFactors",
                type: "bigint",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FailedAttemptCount",
                table: "ToamaisutaaUserTwoFactors");

            migrationBuilder.DropColumn(
                name: "FirstFailedAttemptAt",
                table: "ToamaisutaaUserTwoFactors");

            migrationBuilder.DropColumn(
                name: "LockedOutUntil",
                table: "ToamaisutaaUserTwoFactors");
        }
    }
}
