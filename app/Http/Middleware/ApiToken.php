<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ApiToken
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken() ?: $request->header('X-Api-Token');

        $user = $token ? User::where('api_token', $token)->first() : null;

        if (! $user) {
            return response()->json(['message' => 'Nao autenticado.'], 401);
        }

        $request->setUserResolver(fn () => $user);

        return $next($request);
    }
}
