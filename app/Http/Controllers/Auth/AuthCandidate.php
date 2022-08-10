<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use App\Models\User;
use App\Models\Roles;

class AuthCandidate extends Controller
{
    const ROLE_NAME = "candidate";
    public $role;
    public $fb;

    function __construct() {
        $this->role =  Roles::where('name', self::ROLE_NAME)->first();
    }

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
     *      @OA\Property(property="password_confirmation", type="string"),
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
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6|confirmed',
            'password_confirmation' => 'required|min:6'
        ],[
            'email.unique' => trans('messages.register.error.isExists',['value'=> 'email']),
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $input['role_id'] = $this->role->id;
        $resp = User::create($input);
        $this->createOauthClient($resp->id, $input['name']);

        return response()->json(['message' => trans('messages.register.success')]);            
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
            'email' => 'required|email',
            'password' => 'required',
        ]);
        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }

        $user = DB::table('users')
                ->leftJoin('roles', 'users.role_id', '=', 'roles.id')
                ->select('users.*', 'roles.name as role_name')
                ->where('users.email',$request->email)
                ->first();

        if ($user) {
            if (Hash::check($request->password, $user->password)) {
                $oauth_clients = DB::table('oauth_clients')->where('user_id', $user->id)->first();

                $resp =  $this->createOauthAccessRefreshToken([
                    'user' => $user,
                    'client_id' => $oauth_clients->id,
                    'client_secret' => $oauth_clients->secret,
                    'username' => $request->email,
                    'password' => $request->password,
                ]);

                return response()->json($resp, 200);
            } else {
                return response()->json(["message" => "Password mismatch"], 422);
            }
        } else {
            return response()->json(['error' => 'User not exists'], 401);
        }
    }

    /**
     * Login facebook
     *
     * @param  associative array $data
     * @return associative array
    */ 
    public function loginFacebook(Request $request){
        $validator = Validator::make($request->all(), [
            'access_token' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }

        $user_details = "https://graph.facebook.com/me?fields=id,name,email,picture&access_token=" .$request->access_token;
        try {
            $response = file_get_contents($user_details);
            $response = json_decode($response);
            $user = DB::table('users')
            ->leftJoin('roles', 'users.role_id', '=', 'roles.id')
            ->select('users.*', 'roles.name as role_name')
            ->where('users.email',$response->email)
            ->first();

            $password_random = Str::uuid()->toString();
            $createUser = NULL;
            if ($user) {
                $createUser = $user;
            }else{
                $input = $request->all();
                $input['password'] = bcrypt($password_random);
                $input['picture'] = $request->picture;
                $input['role_id'] = $this->role->id;
                $createUser = User::create($input);
                $this->createOauthClient($createUser->id, $input['name']);
            }

            $oauth_clients = DB::table('oauth_clients')->where('user_id', $createUser->id)->first();
            $resp =  $this->createOauthAccessRefreshToken([
                'user' => $createUser,   
                'client_id' => $oauth_clients->id,
                'client_secret' => $oauth_clients->secret,
                'username' => $request->email,
                'password' => $password_random,
            ]);

            return response()->json($resp, 200);

        } catch (\Throwable $th) {
            return response()->json([''=> "something wrong"], 200);
        }
    }
}
