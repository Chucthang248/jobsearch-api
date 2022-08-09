<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Client;
use App\Models\Roles;

class AuthCandidate extends Controller
{

    const ROLE_NAME = "candidate";

    /**
     * 
     * @OA\Post(
     *   path="/api/candidate/register",
     *   tags={"Candidate"},
     *   summary="Candidate",
     *   operationId="Candidate",
     * 
     *  @OA\RequestBody(
     *      description= "Register candidate",
     *      required=true,
     *      @OA\JsonContent(
     *      type="object",
     *      @OA\Property(property="name", type="string"),
     *      @OA\Property(property="email", type="string"),
     *      @OA\Property(property="password", type="string"),
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
    public function register(Request $request)
    {
        $role = Roles::where('name', self::ROLE_NAME)->first();
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $input['role_id'] = $role->id;
        $resp = User::create($input);

        Client::newFactory()->asPasswordClient()->create([
            'user_id' => $resp->id,
            'name' => $input['name'],
            'provider' => config('auth.guards.api.provider'),
            'redirect' => ''
        ]);

        return response()->json(['message' => trans('messages.register.value',  ['value' => self::ROLE_NAME])]);
    }

    /**
     * 
     * @OA\Post(
     *   path="/api/candidate/login",
     *   tags={"Candidate"},
     *   summary="login",
     *   operationId="login",
     * 
     *  @OA\RequestBody(
     *      description= "Login candidate",
     *      required=true,
     *      @OA\JsonContent(
     *      type="object",
     *      @OA\Property(property="email", type="string"),
     *      @OA\Property(property="password", type="string"),
     *   )
     *  ),
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
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required',
        ]);
        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }
        $user = User::where('email', $request->email)->first();
        if ($user) {
            if (Hash::check($request->password, $user->password)) {
                $oauth_clients = DB::table('oauth_clients')->where('user_id', $user->id)->first();

                $response = Http::withHeaders([
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ])->asForm()->post(config('app.url') . '/oauth/token', [
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

                return response()->json(['user' => $user, 'access_token' => $access_token, 'refresh_token' => $user->id . "." . $refresh_token]);
            } else {
                return response()->json(["message" => "Password mismatch"], 422);
            }
        } else {
            return response()->json(['error' => 'User not exists'], 401);
        }
    }

    /**
     * 
     * @OA\Get(
     *   path="/api/candidate/test",
     *   tags={"Candidate"},
     *   summary="test",
     *   operationId="test",
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
    public function test()
    {
        return response()->json(['access_token' => "token"]);
    }
}
