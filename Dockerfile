FROM microsoft/dotnet

ENV RESOLVER_ID -

RUN mkdir /app
WORKDIR /app
RUN mkdir /Web
RUN mkdir /wwwroot
RUN mkdir /Properties

COPY /Kres.Man/*.csproj ./
COPY /Kres.Man/*.json ./
COPY /Kres.Man/Web/*.html ./Web/
COPY /Kres.Man/Properties/*.json ./Properties/
COPY /Kres.Man/*.pfx ./
COPY /Kres.Man/*.config ./
COPY /Kres.Man/startup.sh /usr/local/bin/startup.sh

RUN dotnet restore
RUN chmod +x /usr/local/bin/startup.sh

COPY . ./

CMD /usr/local/bin/startup.sh
