using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AliasServerDb.Migrations
{
    /// <inheritdoc />
    public partial class AddDurableSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_UserEncryptionKeys_UserId",
                table: "UserEncryptionKeys");

            migrationBuilder.DropIndex(
                name: "IX_AliasVaultUserRefreshTokens_UserId",
                table: "AliasVaultUserRefreshTokens");

            migrationBuilder.AddColumn<Guid>(
                name: "ApprovingSessionId",
                table: "MobileLoginRequests",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SessionId",
                table: "AliasVaultUserRefreshTokens",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateTable(
                name: "UserSessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserSessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserSessions_AliasVaultUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AliasVaultUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            // Preserve existing refresh tokens while requiring old access tokens to refresh once.
            migrationBuilder.Sql("UPDATE \"AliasVaultUserRefreshTokens\" SET \"SessionId\" = \"Id\"");
            migrationBuilder.Sql("INSERT INTO \"UserSessions\" (\"Id\", \"UserId\", \"CreatedAt\") SELECT \"Id\", \"UserId\", \"CreatedAt\" FROM \"AliasVaultUserRefreshTokens\"");
            // Keep every historical key; only resolve ambiguous primary flags before adding uniqueness.
            migrationBuilder.Sql("WITH ranked AS (SELECT \"Id\", ROW_NUMBER() OVER (PARTITION BY \"UserId\" ORDER BY \"UpdatedAt\" DESC, \"Id\" DESC) AS n FROM \"UserEncryptionKeys\" WHERE \"IsPrimary\") UPDATE \"UserEncryptionKeys\" k SET \"IsPrimary\" = FALSE FROM ranked r WHERE k.\"Id\" = r.\"Id\" AND r.n > 1");

            migrationBuilder.CreateIndex(
                name: "IX_UserEncryptionKeys_UserId",
                table: "UserEncryptionKeys",
                column: "UserId",
                unique: true,
                filter: "\"IsPrimary\" = TRUE");

            migrationBuilder.CreateIndex(
                name: "IX_AliasVaultUserRefreshTokens_SessionId",
                table: "AliasVaultUserRefreshTokens",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_AliasVaultUserRefreshTokens_UserId_SessionId",
                table: "AliasVaultUserRefreshTokens",
                columns: new[] { "UserId", "SessionId" });

            migrationBuilder.CreateIndex(
                name: "IX_UserSessions_UserId",
                table: "UserSessions",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_AliasVaultUserRefreshTokens_UserSessions_SessionId",
                table: "AliasVaultUserRefreshTokens",
                column: "SessionId",
                principalTable: "UserSessions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AliasVaultUserRefreshTokens_UserSessions_SessionId",
                table: "AliasVaultUserRefreshTokens");

            migrationBuilder.DropTable(
                name: "UserSessions");

            migrationBuilder.DropIndex(
                name: "IX_UserEncryptionKeys_UserId",
                table: "UserEncryptionKeys");

            migrationBuilder.DropIndex(
                name: "IX_AliasVaultUserRefreshTokens_SessionId",
                table: "AliasVaultUserRefreshTokens");

            migrationBuilder.DropIndex(
                name: "IX_AliasVaultUserRefreshTokens_UserId_SessionId",
                table: "AliasVaultUserRefreshTokens");

            migrationBuilder.DropColumn(
                name: "ApprovingSessionId",
                table: "MobileLoginRequests");

            migrationBuilder.DropColumn(
                name: "SessionId",
                table: "AliasVaultUserRefreshTokens");

            migrationBuilder.CreateIndex(
                name: "IX_UserEncryptionKeys_UserId",
                table: "UserEncryptionKeys",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AliasVaultUserRefreshTokens_UserId",
                table: "AliasVaultUserRefreshTokens",
                column: "UserId");
        }
    }
}
