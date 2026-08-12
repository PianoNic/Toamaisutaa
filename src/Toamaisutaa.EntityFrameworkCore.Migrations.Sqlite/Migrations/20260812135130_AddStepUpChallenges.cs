using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddStepUpChallenges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "FamilyId",
                table: "ToamaisutaaTwoFactorChallenges",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Purpose",
                table: "ToamaisutaaTwoFactorChallenges",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FamilyId",
                table: "ToamaisutaaTwoFactorChallenges");

            migrationBuilder.DropColumn(
                name: "Purpose",
                table: "ToamaisutaaTwoFactorChallenges");
        }
    }
}
