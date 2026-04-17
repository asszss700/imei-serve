FROM php:8.2-cli

WORKDIR /app

COPY index.php .

RUN mkdir -p /tmp && chmod 777 /tmp

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "index.php"]
