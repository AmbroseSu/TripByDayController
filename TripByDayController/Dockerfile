# Sử dụng base image của Java
FROM openjdk:17-slim

# Thiết lập thư mục làm việc
WORKDIR /app

# Sao chép file pom.xml và các file cần thiết khác vào thư mục làm việc
COPY ./pom.xml .
COPY ./src ./src
COPY mvnw .
COPY .mvn .mvn

# Cài đặt Maven
RUN apt-get update && apt-get install -y maven

#COPY --from=tripbydayrepository /.m2/repository /root/.m2/repository/com/ambrose
#COPY --from=tripbydayservice /.m2/repository /root/.m2/service/com/ambrose
# Xây dựng ứng dụng
#RUN ./mvnw clean package -DskipTests
RUN ./mvnw dependency:go-offline
EXPOSE 8080
CMD ["./mvnw", "spring-boot:run"]
# Mở cổng 8080


# Chạy ứng dụng
