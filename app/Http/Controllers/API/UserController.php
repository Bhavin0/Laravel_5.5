<?php

namespace App\Http\Controllers\API;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Requests;
use JWTAuth;
use JWTAuthException;
use App\User;
use Validator;

class UserController extends Controller
{
    //
    public function __construct()
    {
        $this->msg['data']=null;
        $this->msg['message']='';
        $http_code=200;
    }

    //Method use for signup
    public function signup(Request $request)
    {
    	//Check validation at login time
    	$validator = Validator::make($request->all(),[
    		'name'=>'required|max:255',
    		'email'=>'required|email|unique:users',
    		'password'=>'required'
		 ]);
    	//if validation done successfully
    	if(!$validator->fails())
    	{
	    	try
	    	{
		    	$user=new User;
		    	//Create  a user and record into a database.
		    	$user->name=$request->name;
		    	$user->email=$request->email;
		    	$user->password=bcrypt($request->password);
		    	//if userstored successfully 
		    	if($user->save())
		    	{
		    		$this->msg['message']='Registered successfully...';
		    		$http_code=200;
		    	}
		    	else
		    	{
		    		//Error occurs in insertion
		    		$this->msg['message']='Error  in insertion...';
			    	$http_code=400;
		    	}
	    	}
	    	catch(Exception $e)
	    	{
	    		//If any exception occurs
	    		$this->msg['message']='Internal server error...';
			    $http_code=500;
	    	}
	    }
	    else
	    {	
	    	//Validation fails
	    	$this->msg['message']=$validator->messages();
			$http_code=400;
	    }
	    //returns json response
    	return response()->json($this->msg,$http_code);

    }
    //Method use for login
    public function signin(Request $request){
    	//Validate request
    	$validator = Validator::make($request->all(),[
    		'email'=>'required|email',
    		'password'=>'required'
		 ]);
    	if(!$validator->fails())
    	{
	        $credentials = $request->only('email', 'password');
	        $token = null;
	        try {
	        		//verify user and generate token
	        		$token=JWTAuth::attempt($credentials);
	        		if($token)
	        		{
	        			$user=User::where('email',$request->email)->first();
	        			$user['token']=$token;
	        			
	        			//returns if user verified
	        			$this->msg['data']=$user;
	        			$this->msg['message']="Login successfully...";
	        			$http_code=200;
	        		}
	        		else
	        		{
	        			//returns if user unauthorised
	        			$this->msg['data']=null;
	        			$this->msg['message']="Unauthorised...";
	        			$http_code=401;
	        		}

	        } catch (JWTAuthException $e) {
	        		//Error or exceptoin occurs
	            	$this->msg['data']=null;
	        		$this->msg['message']="Internal server Error";
	        		$http_code=500;
	        }
	    }
	    else
	    {
	    	//if validators fails
	    	$this->msg['message']=$validator->messages();
			$http_code=400;	
	    }
	    //returns json response
	    return response()->json($this->msg,$http_code);
    }
}
