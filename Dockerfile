FROM microsoft/dotnet

RUN mkdir /app
WORKDIR /app

COPY /Sink/*.csproj ./
COPY /Sink/appsettings.json ./
COPY /Sink/log4net.config ./
RUN dotnet restore

COPY . ./

#RUN dotnet run

