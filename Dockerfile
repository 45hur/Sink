FROM microsoft/aspnetcore-build AS build-env

ENV RESOLVER_ID -

RUN mkdir /app
WORKDIR /app

COPY /Kres.Man/*.csproj ./
RUN dotnet restore

RUN dotnet new global.json

COPY /Kres.Man/ ./
RUN dotnet publish -c Release -o out

FROM microsoft/aspnetcore
WORKDIR /app
COPY --from=build-env /app/out .
COPY --from=build-env /app/sinkhole.pfx ./

COPY /Kres.Man/startup.sh /usr/local/bin/startup.sh 
RUN chmod +x /usr/local/bin/startup.sh

ENTRYPOINT ["/usr/local/bin/startup.sh"]
