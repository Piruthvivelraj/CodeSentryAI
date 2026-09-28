using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CodeSentry.API.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddIsAdminToLocalUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsAdmin",
                table: "LocalUsers",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsAdmin",
                table: "LocalUsers");
        }
    }
}
