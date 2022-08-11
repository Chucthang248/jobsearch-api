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
            'password' => 'required|string|min:6|confirmed|regex:/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{6,}$/',
            'password_confirmation' => 'required|string|min:6|regex:/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{6,}$/'
        ],[
            'email.unique' => trans('messages.error.isExists',['value'=> 'email']),
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 401);
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $input['role_id'] = $this->role->id;
        $resp = User::create($input);
        $this->createOauthClient($resp->id, $input['name']);

        return response()->json(['success' => trans('messages.success.value',['value'=> 'register'])]);            
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
                return response()->json(["errors" => trans('messages.error.invalid',['value'=> 'password'])], 422);
            }
        } else {
            return response()->json(['errors' => trans('messages.error.notExists',['value'=> 'user'])], 401);
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
        $enpoint = "https://graph.facebook.com/me?fields=id,name,email,picture&access_token=";
        $resp = $this->executeLogin($enpoint, $request);
        return response()->json(['data' => $resp], 200);
    }

    /**
     * Login google
     *
     * @param  associative array $data
     * @return associative array
    */ 
    public function loginGoogle(Request $request){
        $validator = Validator::make($request->all(), [
            'access_token' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }
        $enpoint = "https://oauth2.googleapis.com/tokeninfo?id_token=";
        $resp = $this->executeLogin($enpoint, $request);
        return response()->json(['data' => $resp], 200);
    }

    /**
     * Login linkedin
     *
     * @param  associative array $data
     * @return associative array
    */ 
    public function loginLinkedin(Request $request){
        $validator = Validator::make($request->all(), [
            'code' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }

        $client = new \GuzzleHttp\Client([
            'base_uri' => 'https://www.linkedin.com',
        ]);

       $client_id = "78ifr7gvptfljx";
       $client_secret = "7Xx3hx6CMuGdkajb";

        $response = $client->request('POST', '/oauth/v2/accessToken', [
            'form_params' => [
                "grant_type" => "authorization_code",
                "code" => $request->code,
                "client_id" => $client_id,
                "client_secret" => $client_secret,
                "redirect_uri" => "http://localhost:21352/login_linkedin.php",
            ],
        ]);
       $result = $response->getBody()->getContents();
       $access_token = json_decode($result)->access_token;

       // get user details
        $client2 = new \GuzzleHttp\Client([
            'base_uri' => 'https://api.linkedin.com',
        ]);

        $response2 = $client2->request('GET', '/rest/me', [
            "headers" => [
                "Authorization" => "Bearer ". $access_token
            ]
        ]);
        
        $res2 = json_decode($response2->getBody());
        
        // $fields = [
        //     'id',
        //     'firstName',
        //     'lastName',
        // ];
        
        // $response2 = $client2->request('GET', '/v2/me', [
        //     "headers" => [
        //         "Authorization" => "Bearer ". $access_token
        //     ],
        //     "query" => [
        //         'projection' => '(' . implode(',', $fields) . ')',
        //     ]
        // ]);
        
        // $res2 = json_decode($response2->getBody());
        

        // // get email address
        // $email = '';
        // $response3 = $client2->request('GET', '/v2/emailAddress', [
        //     "headers" => [
        //         "Authorization" => "Bearer ". $access_token
        //     ],
        //     'query' => [
        //         'q' => 'members',
        //         'projection' => '(elements*(handle~))',
        //     ]
        // ]);
        
        // $res3 = json_decode($response3->getBody());
        
        // foreach ($res3->elements as $element) {
        //     foreach ($element as $key=>$value) {
        //         if ('handle~' == $key) {
        //             $email = $value->emailAddress;
        //         }
        //     }
        // }
        
        // $locale = $res2->firstName->preferredLocale->language . '_' . $res2->firstName->preferredLocale->country;
        // $in_data['name'] = $res2->firstName->localized->$locale . ' ' . $res2->lastName->localized->$locale;
        // $in_data['id'] = $res2->id;
        // $in_data['email'] = $email;
        //$in_data['picture'] = $picture;
        return response()->json(['access_token' => $res2], 200);
    }

    /**
     * Login google
     *
     * @param $enpoint array $data
     * @param Request $request
     * @return json
    */ 
    public function executeLogin($enpoint, $request){
        $user_details = $enpoint.$request->access_token;
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
                $input['password'] = bcrypt($password_random);
                $input['name']    = $response->name;
                $input['email']   = $response->email;
                $input['picture'] = $response->picture;
                $input['role_id'] = $this->role->id;
                $createUser = User::create($input);
                $this->createOauthClient($createUser->id, $response->name);
            }
            $oauth_clients = DB::table('oauth_clients')->where('user_id', $createUser->id)->first();
            $resp =  $this->createOauthAccessRefreshToken([
                'user' => $createUser,   
                'client_id' => $oauth_clients->id,
                'client_secret' => $oauth_clients->secret,
                'username' => $response->email,
                'password' => $password_random,
            ]);
            
            return $resp;
        } catch (\Throwable $th) {
            throw $th;
        }
    }

    public function test(){
        return response()->json(['data' => "okay"], 200);
    }
}
