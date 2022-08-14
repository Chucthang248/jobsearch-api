<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\TokenRepository; 
use Laravel\Passport\RefreshTokenRepository;

class AuthController extends Controller
{

    /**
     * 
     * @OA\Post(
     *   path="/api/logout",
     *   tags={"logout"},
     *   summary="logout",
     *   operationId="logout",
     *   security={{"bearerAuth":{}}},
     * 
     *  @OA\Response(
     *       response=200,
     *       description="successful operation",
     *   ),
     *   @OA\Response(
     *      response=401,
     *       description="Unauthenticated"
     *   ),
     *   @OA\Response(
     *      response=400,
     *      description="Bad Request"
     *   ),
     *   @OA\Response(
     *      response=404,
     *      description="not found"
     *   ),
     *   @OA\Response(
     *       response=403,
     *       description="Forbidden"
     *   )
     *)
    */
    public function logout(Request $request){

        $headers = $request->header('Authorization');
        
        if(empty($headers)){
            return response(['errors'=> "reqired access_token"], 422);
        }

        $tokenRepository = app(TokenRepository::class);
        $refreshTokenRepository = app(RefreshTokenRepository::class);

        $tokenRepository = new TokenRepository();
        $access_token_id = $request->user()->token()->id;
        // Revoke an access token...
        $tokenRepository->revokeAccessToken($access_token_id);

        // Revoke all of the token's refresh tokens...
        $refreshTokenRepository->revokeRefreshTokensByAccessTokenId($access_token_id);

        return response()->json(['message'=> "logout success"]);
    }

    /**
     * 
     * @OA\Post(
     *   path="/api/refresh_token",
     *   tags={"refresh token"},
     *   summary="refresh_token",
     *   operationId="refresh_token",
     * 
     *  @OA\RequestBody(
     *      description= "Refresh token.",
     *      required=true,
     *      @OA\JsonContent(
     *      type="object",
     *      @OA\Property(property="refresh_token", type="string"),
     *   )
     *  ),
     *  @OA\Response(
     *       response=200,
     *       description="successful operation",
     *       @OA\JsonContent(
     *       type="object",
     *          @OA\Property(property="message", type="string"),
     *        )
     *   ),
     *   @OA\Response(
     *      response=401,
     *       description="Unauthenticated"
     *   ),
     *   @OA\Response(
     *      response=400,
     *      description="Bad Request"
     *   ),
     *   @OA\Response(
     *      response=404,
     *      description="not found"
     *   ),
     *   @OA\Response(
     *       response=403,
     *       description="Forbidden"
     *   )
     *)
    */
    public function refreshToken(Request $request){

        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required',
            'user_id' => 'required',
        ]);

        if ($validator->fails()) {
            return response(['errors'=>$validator->errors()->all()], 422);
        }
        $oauth_clients = DB::table('oauth_clients')->where('user_id', $request->input('user_id'))->first();

        $response = Http::withHeaders([
            'Content-Type' => 'application/x-www-form-urlencoded',
           ])->asForm()->post(config('app.url').'/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $request->input('refresh_token'),
                'client_id' => $oauth_clients->id,
                'client_secret' => $oauth_clients->secret,
                'scope' => [],
           ]);
         
           $result = $response->getBody()->getContents();
           $access_token = json_decode($result)->access_token;
           $refresh_token = json_decode($result)->refresh_token;

        return response()->json(['access_token' => $access_token, 'refresh_token' => $refresh_token]);
    }

}