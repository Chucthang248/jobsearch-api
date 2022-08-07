<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Http;

class AuthController extends Controller
{
    
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

                $oauth_clients = DB::table('oauth_clients')->where('password_client', 1)->first();
          
                $response = Http::withHeaders([
                    'Content-Type' => 'application/x-www-form-urlencoded',
                   ])->asForm()->post('http://jobsearch.local/oauth/token', [
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

                return response()->json(['access_token' => $access_token, 'refresh_token' => $refresh_token]);
            }else {
                $response = ["message" => "Password mismatch"];
                return response($response, 422);
            }
        }
        else { 
            return response()->json(['error'=>'Unauthorised'], 401); 
        } 
    }

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
        User::create($input); 

        $response = Http::withHeaders([
            'Content-Type' => 'application/x-www-form-urlencoded',
           ])->asForm()->post('http://jobsearch.local/oauth/clients', [
                'name' => 'New Client Name',
                'redirect'=> 'http://example.com/callback'
           ]);

        $result = $response->getBody()->getContents();

        return response()->json(['data' => $result]);
    }
    
    public function refreshToken(Request $request){

        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required',
        ]);

        if ($validator->fails()) {
            return response(['errors'=>$validator->errors()->all()], 422);
        }
      
        $oauth_clients = DB::table('oauth_clients')->where('password_client', 1)->first();

        $response = Http::withHeaders([
            'Content-Type' => 'application/x-www-form-urlencoded',
           ])->asForm()->post('http://jobsearch.local/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $request->input('refresh_token'),
                'client_id' => $oauth_clients->id,
                'client_secret' => $oauth_clients->secret,
                'scope' => '',
           ]);
         
        $result = $response->getBody()->getContents();

        return response()->json(['refresh_token' =>   $result]);
    }

    public function test(){
        return response()->json(['data' => 'DONE']);
    }
}