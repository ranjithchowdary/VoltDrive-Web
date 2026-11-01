FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
RUN curl -fsSL -o postgresql.jar https://repo1.maven.org/maven2/org/postgresql/postgresql/42.7.4/postgresql-42.7.4.jar
COPY backend/src/VoltDriveServer.java .
RUN mkdir out && javac --release 21 -d out VoltDriveServer.java

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /src/out /app/out
COPY --from=build /src/postgresql.jar /app/postgresql.jar
COPY frontend /app/frontend
ENV FRONTEND_DIR=/app/frontend
EXPOSE 10000
CMD ["sh","-c","java -cp /app/out:/app/postgresql.jar VoltDriveServer"]
