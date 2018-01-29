FROM microsoft/dotnet

RUN mkdir /app
WORKDIR /app

COPY /Kres.Man/*.csproj ./
COPY /Kres.Man/appsettings.json ./
COPY /Kres.Man/log4net.config ./
RUN dotnet restore

COPY . ./

#RUN dotnet run

