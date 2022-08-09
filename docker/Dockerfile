FROM php:8.0-rc-apache-buster

USER root

WORKDIR /var/www/html

COPY ./ /var/www/html/

RUN apt-get update && apt-get install nano && apt-get install -y \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libpq-dev \
    git \
    zip \
    curl \
    sudo \
    unzip \
	&& docker-php-ext-configure gd --with-freetype --with-jpeg \
	&& docker-php-ext-install -j$(nproc) gd \
    && docker-php-ext-install pdo pdo_pgsql

RUN a2enmod rewrite

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

COPY docker/000-default.conf /etc/apache2/sites-available/000-default.conf

RUN sudo chown -R $USER:www-data storage
RUN sudo chown -R $USER:www-data bootstrap/cache
RUN chmod -R 775 storage
RUN chmod -R 775 bootstrap/cache

RUN chmod -R 777 storage/logs/laravel.log
RUN chmod -R 777 storage/api-docs/api-docs.json