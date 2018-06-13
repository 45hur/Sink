FROM microsoft/dotnet

ENV RESOLVER_ID -

RUN mkdir /app
WORKDIR /app
RUN mkdir /Web

COPY /Kres.Man/*.csproj ./
COPY /Kres.Man/appsettings.json ./
COPY /Kres.Man/Web/*.html ./Web/
COPY /Kres.Man/publiclistenerconfig.json ./
COPY /Kres.Man/log4net.config ./
COPY /Kres.Man/startup.sh /usr/local/bin/startup.sh

RUN dotnet restore
RUN chmod +x /usr/local/bin/startup.sh

COPY . ./

CMD /usr/local/bin/startup.sh
