using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Toamaisutaa.EntityFrameworkCore.Migrations.Postgres.Migrations
{
    /// <summary>
    /// Moves the timestamps introduced with the first schema onto the same Unix-millisecond
    /// representation the password tables use, so every instant in the schema can be range-queried
    /// on both supported providers rather than only on Postgres.
    /// </summary>
    /// <remarks>
    /// Hand-written rather than scaffolded. The generated <c>AlterColumn</c> emits
    /// <c>ALTER COLUMN ... TYPE bigint</c>, which Postgres refuses without a <c>USING</c> clause
    /// because there is no implicit cast from a timestamp to an integer - it would fail on an empty
    /// table just as surely as on a full one. The explicit conversion below also means existing rows
    /// keep their values instead of the column being dropped and recreated.
    /// </remarks>
    public partial class ConvertTimestampsToUnixMilliseconds : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            Convert(migrationBuilder, "ToamaisutaaUsers", "CreatedAt");
            Convert(migrationBuilder, "ToamaisutaaUsers", "UpdatedAt");
            Convert(migrationBuilder, "ToamaisutaaExternalLogins", "CreatedAt");
            Convert(migrationBuilder, "ToamaisutaaExternalLogins", "LastSignInAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            Revert(migrationBuilder, "ToamaisutaaUsers", "CreatedAt");
            Revert(migrationBuilder, "ToamaisutaaUsers", "UpdatedAt");
            Revert(migrationBuilder, "ToamaisutaaExternalLogins", "CreatedAt");
            Revert(migrationBuilder, "ToamaisutaaExternalLogins", "LastSignInAt");
        }

        private static void Convert(MigrationBuilder migrationBuilder, string table, string column) =>
            migrationBuilder.Sql(
                $"""
                 ALTER TABLE "{table}"
                 ALTER COLUMN "{column}" TYPE bigint
                 USING (EXTRACT(EPOCH FROM "{column}") * 1000)::bigint;
                 """);

        // Reading back gives UTC, which is what the converter would have produced anyway: the
        // instant survives the round trip, the original offset does not.
        private static void Revert(MigrationBuilder migrationBuilder, string table, string column) =>
            migrationBuilder.Sql(
                $"""
                 ALTER TABLE "{table}"
                 ALTER COLUMN "{column}" TYPE timestamp with time zone
                 USING TO_TIMESTAMP("{column}" / 1000.0);
                 """);
    }
}
