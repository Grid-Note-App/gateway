# ---------- build stage ----------
FROM eclipse-temurin:25-jdk AS builder

WORKDIR /app

# скопировать wrapper, иначе RUN ./mvnw не найдёт бинарь
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src ./src

RUN chmod +x mvnw
RUN ./mvnw -B clean package -DskipTests

# ---------- runtime stage ----------
FROM eclipse-temurin:25-jre

WORKDIR /app

COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
