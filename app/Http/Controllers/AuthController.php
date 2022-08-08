<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Client;
use Laravel\Passport\TokenRepository; 
use Laravel\Passport\RefreshTokenRepository;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [ 
            'name' => 'required', 
            'email' => 'required|email|unique:users', 
            'password' => 'required', 
        ]);
        if ($validator->fails()) { 
            return response()->json(['error'=>$validator->errors()], 401);            
        }
        $input = $request->all(); 
        $input['password'] = bcrypt($input['password']); 
        $resp = User::create($input); 

        Client::newFactory()->asPasswordClient()->create([
            'user_id' => $resp->id, 
            'name' => $input['name'], 
            'provider'=> config('auth.guards.api.provider'),
            'redirect'=> ''
        ]);

        return response()->json(['message' => 'success']);
    }    

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response(['errors'=>$validator->errors()->all()], 422);
        }
        
        $user = User::where('email', $request->email)->first();
        if ($user) {
            if (Hash::check($request->password, $user->password)) {

                $oauth_clients = DB::table('oauth_clients')->where('user_id', $user->id)->first();

                $response = Http::withHeaders([
                    'Content-Type' => 'application/x-www-form-urlencoded',
                   ])->asForm()->post('http://localhost/oauth/token', [
                        'grant_type' => 'password',
                        'client_id' => $oauth_clients->id,
                        'client_secret' => $oauth_clients->secret,
                        'username' => $request->email,
                        'password' => $request->password,
                        'scope' => '',
                   ]);

                $result = $response->getBody()->getContents();
                $access_token = json_decode($result)->access_token;
                $refresh_token = json_decode($result)->refresh_token;

                return response()->json(['user' => $user, 'access_token' => $access_token, 'refresh_token' => $refresh_token]);

            }else {
                $response = ["message" => "Password mismatch"];
                return response($response, 422);
            }
        }
        else { 
            return response()->json(['error'=>'Unauthorised'], 401); 
        } 
    }

    public function logout(Request $request){

        $validator = Validator::make($request->all(), [
            'user_id' => 'required',
        ]);

        if ($validator->fails()) {
            return response(['errors'=>$validator->errors()->all()], 422);
        }

        $tokenRepository = app(TokenRepository::class);
        $refreshTokenRepository = app(RefreshTokenRepository::class);

        $tokenRepository = new TokenRepository();
        $user = new User();
        $client = new Client();

        $user = $tokenRepository->findValidToken($user, $client);

        // Revoke an access token...
        //$tokenRepository->revokeAccessToken($user->id);

        // Revoke all of the token's refresh tokens...
        //$refreshTokenRepository->revokeRefreshTokensByAccessTokenId($user->id);

        return response()->json(['message'=> $user]);
    }
    
    public function refreshToken(Request $request){

        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required',
        ]);

        if ($validator->fails()) {
            return response(['errors'=>$validator->errors()->all()], 422);
        }
      
        $oauth_clients = DB::table('oauth_clients')->where('user_id', $request->input('user_id'))->first();

        $response = Http::withHeaders([
            'Content-Type' => 'application/x-www-form-urlencoded',
           ])->asForm()->post('http://localhost/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $request->input('refresh_token'),
                'client_id' => $oauth_clients->id,
                'client_secret' => $oauth_clients->secret,
                'scope' => '',
           ]);
         
           $result = $response->getBody()->getContents();
           $access_token = json_decode($result)->access_token;
           $refresh_token = json_decode($result)->refresh_token;

           return response()->json(['access_token' => $access_token, 'refresh_token' => $refresh_token]);
    }
    
    public function test(){
        return response()->json(['data' => 'DONE']);
    }


}