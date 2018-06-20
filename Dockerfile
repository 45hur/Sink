FROM microsoft/aspnetcore-build:2.0 AS build-env

ENV RESOLVER_ID -

RUN mkdir /app
WORKDIR /app

COPY /Kres.Man/*.csproj ./
RUN dotnet restore

RUN dotnet new global.json

COPY /Kres.Man/ ./
RUN dotnet publish -c Release -o out
RUN chmod +x /usr/local/bin/startup.sh
CMD /usr/local/bin/startup.sh

FROM microsoft/aspnetcore:2.0
WORKDIR /app
COPY --from=build-env /app/out .
ENTRYPOINT ["dotnet", "aspnetapp.dll"]
