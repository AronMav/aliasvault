using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AliasServerDb.Migrations
{
    /// <inheritdoc />
    public partial class HashStoredRefreshTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Replace the stored refresh tokens with their SHA-256 hash, matching what the API now
            // writes and looks up. Rewriting the existing rows instead of clearing the table keeps
            // every logged-in device logged in: the token the client holds still resolves to its row.
            migrationBuilder.Sql(
                """
                UPDATE "AliasVaultUserRefreshTokens"
                SET "Value" = encode(sha256(convert_to("Value", 'UTF8')), 'base64'),
                    "PreviousTokenValue" = CASE
                        WHEN "PreviousTokenValue" IS NULL THEN NULL
                        ELSE encode(sha256(convert_to("PreviousTokenValue", 'UTF8')), 'base64')
                    END;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // A hash cannot be turned back into the token it was made from. Dropping the rows is the
            // only way back: every device has to log in again, which is the correct outcome because
            // the previous schema cannot authenticate a hash.
            migrationBuilder.Sql(@"DELETE FROM ""AliasVaultUserRefreshTokens"";");
        }
    }
}
