using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CodeSentry.API.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddIsActiveToLocalUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsActive",
                table: "LocalUsers",
                type: "INTEGER",
                nullable: false,
                defaultValue: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsActive",
                table: "LocalUsers");
        }
    }
}
