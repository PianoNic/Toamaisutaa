using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite.Migrations
{
    /// <summary>
    /// Moves the timestamps introduced with the first schema onto the same Unix-millisecond
    /// representation the password tables use, so every instant in the schema can be range-queried
    /// on both supported providers rather than only on Postgres.
    /// </summary>
    /// <remarks>
    /// The <c>AlterColumn</c> calls are scaffolded; the conversions before them are not. SQLite
    /// changes a column type by rebuilding the table and copying the old values across, and a copy
    /// alone would move ISO-8601 text into an integer column - where it stays text, because column
    /// affinity only converts what already looks like a number, and every later read then fails.
    /// Rewriting the values first means the rebuild has integers to copy.
    /// </remarks>
    public partial class ConvertTimestampsToUnixMilliseconds : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            ToUnixMilliseconds(migrationBuilder, "ToamaisutaaUsers", "CreatedAt");
            ToUnixMilliseconds(migrationBuilder, "ToamaisutaaUsers", "UpdatedAt");
            ToUnixMilliseconds(migrationBuilder, "ToamaisutaaExternalLogins", "CreatedAt");
            ToUnixMilliseconds(migrationBuilder, "ToamaisutaaExternalLogins", "LastSignInAt");

            migrationBuilder.AlterColumn<long>(
                name: "UpdatedAt",
                table: "ToamaisutaaUsers",
                type: "INTEGER",
                nullable: false,
                oldClrType: typeof(DateTimeOffset),
                oldType: "TEXT");

            migrationBuilder.AlterColumn<long>(
                name: "CreatedAt",
                table: "ToamaisutaaUsers",
                type: "INTEGER",
                nullable: false,
                oldClrType: typeof(DateTimeOffset),
                oldType: "TEXT");

            migrationBuilder.AlterColumn<long>(
                name: "LastSignInAt",
                table: "ToamaisutaaExternalLogins",
                type: "INTEGER",
                nullable: true,
                oldClrType: typeof(DateTimeOffset),
                oldType: "TEXT",
                oldNullable: true);

            migrationBuilder.AlterColumn<long>(
                name: "CreatedAt",
                table: "ToamaisutaaExternalLogins",
                type: "INTEGER",
                nullable: false,
                oldClrType: typeof(DateTimeOffset),
                oldType: "TEXT");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            ToIso8601(migrationBuilder, "ToamaisutaaUsers", "CreatedAt");
            ToIso8601(migrationBuilder, "ToamaisutaaUsers", "UpdatedAt");
            ToIso8601(migrationBuilder, "ToamaisutaaExternalLogins", "CreatedAt");
            ToIso8601(migrationBuilder, "ToamaisutaaExternalLogins", "LastSignInAt");

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "UpdatedAt",
                table: "ToamaisutaaUsers",
                type: "TEXT",
                nullable: false,
                oldClrType: typeof(long),
                oldType: "INTEGER");

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "CreatedAt",
                table: "ToamaisutaaUsers",
                type: "TEXT",
                nullable: false,
                oldClrType: typeof(long),
                oldType: "INTEGER");

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "LastSignInAt",
                table: "ToamaisutaaExternalLogins",
                type: "TEXT",
                nullable: true,
                oldClrType: typeof(long),
                oldType: "INTEGER",
                oldNullable: true);

            migrationBuilder.AlterColumn<DateTimeOffset>(
                name: "CreatedAt",
                table: "ToamaisutaaExternalLogins",
                type: "TEXT",
                nullable: false,
                oldClrType: typeof(long),
                oldType: "INTEGER");
        }

        /// <summary>julianday reads the stored offset and answers in UTC, so the instant survives.</summary>
        private static void ToUnixMilliseconds(MigrationBuilder migrationBuilder, string table, string column) =>
            migrationBuilder.Sql(
                $"""
                 UPDATE "{table}"
                 SET "{column}" = CAST(ROUND((julianday("{column}") - 2440587.5) * 86400000.0) AS INTEGER)
                 WHERE "{column}" IS NOT NULL;
                 """);

        private static void ToIso8601(MigrationBuilder migrationBuilder, string table, string column) =>
            migrationBuilder.Sql(
                $"""
                 UPDATE "{table}"
                 SET "{column}" = strftime('%Y-%m-%d %H:%M:%f', "{column}" / 1000.0, 'unixepoch') || '+00:00'
                 WHERE "{column}" IS NOT NULL;
                 """);
    }
}
