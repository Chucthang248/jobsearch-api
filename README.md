RUN: docker-compose up -d --build

access container apache RUN: docker exec -it jobsearch-api_web_1 bash

in container apache RUN: 
                        composer install
                        composer dump-autoload
                        php artisan migrate
                        php artisan db:seed
                        php artisan passport:install
                        php artisan vendor:publish --tag=passport-config
                        php artisan passport:keys   
                        php artisan l5-swagger:generate

note: (have 2 file oauth_private_key, oauth_public_key after run command "php artisan passport:keys", 
copy key 2 file to .env PASSPORT_PRIVATE_KEY ,PASSPORT_PUBLIC_KEY)

view document api: http://localhost:21152/api/documentation

GOOGLE_APP_ID=AIzaSyAouk0FdDCjh37Jd0Bn8OEdGPp9dhKPzCg
GOOGLE_CLIENT_ID=519093123816-i8lg5e5tenlgpkdjva2o8kb7pm5ijttq.apps.googleusercontent.com
GOOGLE_SECRET_ID=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