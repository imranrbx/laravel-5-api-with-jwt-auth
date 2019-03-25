<?php
namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Auth\MustVerifyEmail;

class AuthController extends Controller {
	use MustVerifyEmail;
	/**
	 * Create a new AuthController instance.
	 *
	 * @return void
	 */
	public function __construct() {
		$this->middleware(['auth:api','api.verified'], ['except' => ['login', 'register','resend']]);
		
	}
	/**
	 * Register a User via JWT .
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function register() {
		$validator = Validator::make(request()->all(), [
			'email' => 'required|unique:users',
		]);
		if ($validator->fails()) {
			return response()->json(['error' => 'Error Registering'], 401);
		}
		$user = [
			'name' => request('name'),
			'email' => request('email'),
			'password' => Hash::make(request('password')),
		];

		if (User::create($user)) {
			$credentials = request(['email', 'password']);
			if (!$token = auth('api')->attempt($credentials)) {
				return response()->json(['error' => 'Unauthorized'], 401);
			}
			auth('api')->user()->sendEmailVerificationNotification();
			return $this->respondWithToken($token);
		} else {
			return response()->json(['error' => 'Error Registering'], 401);
		}
	}
	public function update() {
		$validator = Validator::make(request()->all(), [
			'name' => 'required',
			'email' => 'required', Rule::unique('users')->ignore(auth('api')->user()->id),
		]);
		if ($validator->fails()) {
			return response()->json(['error' => 'Error Updating'], 401);
		}
		$user = User::find(auth('api')->user()->id);
		$user->name = request('name');
		$user->email = request('email');
		if ($user->save()) {
			return response()->json(['message' => 'Successfully Updated', 'user' => ['name' => $user->name]], 200);
		} else {
			return response()->json(['error' => 'Error Updating'], 401);
		}
	}
	/**
	 * Get a JWT via given credentials.
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function login() {

		$credentials = request(['email', 'password']);

		if (!$token = auth('api')->attempt($credentials)) {
			return response()->json(['error' => 'Unauthorized'], 401);
		}

		return $this->respondWithToken($token);
	}

	/**
	 * Get the authenticated User.
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function me() {

		return response()->json(auth('api')->user());
	}

	/**
	 * Log the user out (Invalidate the token).
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function logout() {

		auth('api')->logout();
		return response()->json(['message' => 'Successfully logged out']);

	}

	/**
	 * Refresh a token.
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function refresh() {
		return $this->respondWithToken(auth('api')->refresh());
	}
	public function verify()
    {
        // ->route('id') gets route user id and getKey() gets current user id() 
        // do not forget that you must send Authorization header to get the user from the request
        if (request()->route('id') == request()->user()->getKey() &&
            request()->user()->markEmailAsVerified()) {
            event(new Verified(request()->user()));
        }

        return response()->json('Email verified!');

    }
	 /**
     * Resend the email verification notification.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function resend()
    {
    	
    	$credentials = request(['email', 'password']);
    	if (!$token = auth('api')->attempt($credentials)) {
			return response()->json(['error' => 'Unauthorized'], 401);
		}
        if (auth('api')->user()->hasVerifiedEmail()) {
            return response()->json( 'Email Already Verified, You Can Login', 200);
        }

        auth('api')->user()->sendEmailVerificationNotification();
        auth('api')->logout();
        return response()->json('Email Sent For Verification', 200);
    }

	/**
	 * Get the token array structure.
	 *
	 * @param  string $token
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	protected function respondWithToken($token) {
		return response()->json([
			'access_token' => $token,
			'token_type' => 'bearer',
			'expires_in' => auth('api')->factory()->getTTL() * 60,
			'user' => ['name' => auth('api')->user()->name],
		]);
	}
}