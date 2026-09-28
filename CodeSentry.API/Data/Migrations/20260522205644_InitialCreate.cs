using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CodeSentry.API.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "LocalUsers",
                columns: table => new
                {
                    SupabaseId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    LastLogin = table.Column<DateTime>(type: "TEXT", nullable: false),
                    PlanType = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false, defaultValue: "FREE"),
                    ScansThisMonth = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 0),
                    PlanResetDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LocalUsers", x => x.SupabaseId);
                });

            migrationBuilder.CreateTable(
                name: "ScanStates",
                columns: table => new
                {
                    ScanId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Message = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    ProgressPercent = table.Column<int>(type: "INTEGER", nullable: false),
                    RepoSize = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    EstimatedTime = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    Result = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UserId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    HealthScore = table.Column<int>(type: "INTEGER", nullable: false),
                    RepositoryName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanStates", x => x.ScanId);
                });

            migrationBuilder.CreateTable(
                name: "ApiKeys",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    UserId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    KeyValue = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastUsed = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiKeys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ApiKeys_LocalUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "LocalUsers",
                        principalColumn: "SupabaseId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ApiKeys_UserId",
                table: "ApiKeys",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_LocalUsers_Email",
                table: "LocalUsers",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScanStates_CreatedAt",
                table: "ScanStates",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_ScanStates_Status",
                table: "ScanStates",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_ScanStates_UserId",
                table: "ScanStates",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ApiKeys");

            migrationBuilder.DropTable(
                name: "ScanStates");

            migrationBuilder.DropTable(
                name: "LocalUsers");
        }
    }
}
