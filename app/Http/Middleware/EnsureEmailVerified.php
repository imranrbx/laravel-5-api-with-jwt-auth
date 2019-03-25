<?php

namespace App\Http\Middleware;

use Closure;


class EnsureEmailVerified
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
public function handle($request, Closure $next)
    {
        if (!$request->user() || is_null($request->user()->email_verified_at) ) {
            auth('api')->logout();
            return response()->json('Your email address is not verified.', 403);
        }

        return $next($request);
    }
}
