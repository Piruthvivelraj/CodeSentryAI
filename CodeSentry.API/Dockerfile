FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy csproj and restore as distinct layers
COPY ["CodeSentry.API.csproj", "./"]
RUN dotnet restore "CodeSentry.API.csproj"

# Copy everything else and build
COPY . .
RUN dotnet publish "CodeSentry.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# CRITICAL: Install git (required by RepoCloneService and GitHistorySecretScanner)
RUN apt-get update && \
    apt-get install -y git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Expose ports
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

# Create directory for SQLite DB with correct permissions
RUN mkdir -p /app/data && chown -R 1000:1000 /app/data
# Use standard configuration via appsettings.json or external environment variables

ENTRYPOINT ["dotnet", "CodeSentry.API.dll"]
