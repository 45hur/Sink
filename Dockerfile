
FROM microsoft/dotnet

RUN mkdir /app
WORKDIR /app
RUN mkdir /Web

COPY /Kres.Man/*.csproj ./
COPY /Kres.Man/*.pfx ./
COPY /Kres.Man/Web/*.html ./Web/
COPY /Kres.Man/appsettings.json ./
COPY /Kres.Man/publiclistenerconfig.json ./
COPY /Kres.Man/log4net.config ./
COPY /Kres.Man/*.csv ./

RUN dotnet restore

COPY . ./

#RUN dotnet run

