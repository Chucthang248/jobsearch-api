<?php

namespace App\Helpers;

use DateInterval;
use DateTimeImmutable;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\AuthCode;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Client as PassportClient;
use League\OAuth2\Server\CryptTrait;

class CustomOauth2{
    use CryptTrait;
    private $auth_code_id;
    private $authcode;
    private $authCodeTTL;
    private $authCodeRepository;
    private $scopes;
    private $encryptkey;
    private $userId;
    private $clientSecret;

    public function setUserId($userId){
        $this->userId = $userId;
    }

    public function getUserId(){
        return $this->userId;
    }

    public function setClientSecret($clientSecret){
        $this->clientSecret = $clientSecret;
    }

    public function getClientSecret(){
        return $this->clientSecret;
    }

    public function __construct()
    {
        $this->auth_code_id = bin2hex(random_bytes(40));
        $this->authcode = new AuthCode;
        $this->authCodeTTL  = new DateInterval('PT10M');
        $this->authCodeRepository = new AuthCodeRepository();
        $this->scopes = new Scope('');
        $this->encryptkey = app('encrypter')->getKey();
    }


    /**
     * create oauth clients
     *
     * @param  $user_id, $name
     * @return associative array
    */ 
    public function createOauthClient($user_id, $name){
        PassportClient::newFactory()->asClientCredentials()->create([
            'user_id' => $user_id,
            'name' => $name,
            'provider' => config('auth.guards.api.provider'),
            'redirect' => config('app.url') . '/auth/callback'
        ]);
    }

        /**
     * create access token and refresh token
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
        return ['access_token' => $access_token, 'refresh_token' => $refresh_token];
    }

    public function createAuthCode($client){
        
        $this->authcode->setIdentifier($this->auth_code_id);
        $this->authcode->setUserIdentifier($this->getUserId());
        $this->authcode->setRedirectUri(implode(",",$client->getRedirectUri()));
        $this->authcode->setClient($client);
        
        $this->authCodeRepository->persistNewAuthCode($this->authcode);
       
        $payload = [
            'client_id'             => $this->authcode->getClient()->getIdentifier(),
            'redirect_uri'          => $this->authcode->getRedirectUri(),
            'auth_code_id'          => $this->authcode->getIdentifier(),
            'scopes'                => $this->scopes->getIdentifier(),
            'user_id'               => $this->authcode->getUserIdentifier(),
            'expire_time'           => (new DateTimeImmutable())->add($this->authCodeTTL)->getTimestamp(),
            'code_challenge'        => "",
            'code_challenge_method' => "",
        ];

        $jsonPayload = \json_encode($payload);
        $this->setEncryptionKey($this->encryptkey);
        $code =  $this->encrypt($jsonPayload);
       
        $data['client_id'] = $payload['client_id'];
        $data['client_secret'] = $this->getClientSecret();
        $data['redirect_uri'] = $payload['redirect_uri'];
        $data['code'] = $code;
       
        $datatest['k1'] = $payload;
        $datatest['k2'] = $data;
        return $data;
    }
   
    public function createToken(Client $client){
        $data =  $this->createAuthCode($client);
        $response = Http::withHeaders([
            'Content-Type' => 'application/x-www-form-urlencoded',
        ])->asForm()->post(config('app.url') . '/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $data['client_id'],
            'client_secret' => $data['client_secret'],
            'redirect_uri' => $data['redirect_uri'],
            'code' => $data['code'],
        ]);
        return $response;
    }
}