<?php

namespace App\Helpers;

use Illuminate\Support\Facades\Http;
use Laravel\Passport\Client;

trait Oauth{

    /**
     * Does something interesting
     *
     * @param  $user_id, $name
     * @return associative array
    */ 
    public function createOauthClient($user_id, $name){
        Client::newFactory()->asPasswordClient()->create([
            'user_id' => $user_id,
            'name' => $name,
            'provider' => config('auth.guards.api.provider'),
            'redirect' => ''
        ]);
    }

    /**
     * Does something interesting
     *
     * @param  associative array $data
     * @return associative array
    */ 
    public function createOauthAccessRefreshToken($data){
        $user = $data['user'];
        $response = Http::withHeaders([
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->asForm()->post(config('app.url') . '/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $data['client_id'],
            'client_secret' => $data['client_secret'],
            'username' => $data['username'],
            'password' => $data['password'],
            'scope' => '',
        ]);

        $result = $response->getBody()->getContents();
        $access_token = json_decode($result)->access_token;
        $refresh_token = json_decode($result)->refresh_token;
        unset($user->password);
        return ['user' => $user, 'access_token' => $access_token, 
                'refresh_token' => $user->id . "." . $refresh_token];
    }
}