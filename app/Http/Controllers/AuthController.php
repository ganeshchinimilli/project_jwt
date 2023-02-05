<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Validator;
use Auth;
use App\Models\User;
// use factory;
use JWTAuth;

class AuthController extends Controller
{
    public function _construct(){
        $this->middleware('auth:api',['except'=>'login','register']);
    }
    public function register(request $request){
        $validator = Validator::make($request->all(),[
            'name' =>'required',
            'email' =>'required|unique:users',
            'password' =>'required|confirmed',
            'password_confirmation' => 'required|same:password'
        ]);
        if($validator->fails()){
            $errorString = implode(",",$validator->messages()->all());
             return response()->json([
                'message'=>$errorString,
                'status'=>false,
             ],400);
        }

        $user = User::create(array_merge($validator->validated(),
            ['password'=>bcrypt($request->password)]
        ));
        return response()->json([
            'message'=>'User Registration Successfull',
            'status'=>true,
            'user'=>$user,
        ],201);

    }
    public function login(Request $request){
        $validator = Validator::make($request->all(),[
            'email' =>'required||exists:users',
            'password' =>'required',
        ]);
        if($validator->fails()){
            $errorString = implode(",",$validator->messages()->all());
            return response()->json([
                'message'=>$errorString,
                'status'=>false,
             ],400);
       }
       if(!$token =auth()->attempt($validator->validated())){
        return response()->json(['message'=>'Unauthorized','status'=>false],401);
       };
       return $this->createNewToken($token);
    }

    public function createNewToken($token){
        return response()->json(
        ['access_token'=>$token,
        'token_type'=>'bearer',
        'expires_in'=>Auth::guard()->factory()->getTTL() * 60,
        'user'=>auth()->user(),
    ]);
    }


    public function logout(){
        $user = auth()->logout();
        return response()->json([
            'message'=>'Logged out Successfully',
            'status'=>true,
            'user'=>$user,
        ],200);
    }
    public function profile(Request $request){
        // print_r($request);
      return response()->json([
        'message'=>'success',
        'status'=>true,
        'user'=>auth()->user(),
      ]);

    }
    public function guard()
    {
        return Auth::guard('api');
    }
    public function api(){
        $result_length = 0;
        $result_data = [];
        while($result_length<5){
            $ch = curl_init();
            curl_setopt($ch,CURLOPT_URL,'https://api.kanye.rest');
            curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
            curl_Setopt($ch,CURLOPT_TIMEOUT,10);
            $result = curl_exec($ch);
            $result = json_decode($result,true);
            curl_close($ch);
            if(!empty($result)){
                if(!in_array($result_data,$result)){
                    array_push($result_data,$result);
                    $result_length = $result_length+1;
                };
            };
        };
        // print_r($result_data);
        return  response()->json([
            'status' =>1,
            'message' =>'success',
            'data'=>$result_data
        ]);



    }

}
