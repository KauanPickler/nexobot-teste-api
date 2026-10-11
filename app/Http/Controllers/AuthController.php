<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * Cria uma nova conta (nome, e-mail, telefone e senha).
     */
    public function register(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'min:3', 'max:120'],
            'email' => ['required', 'string', 'email:rfc', 'max:190', 'unique:users,email'],
            'phone' => ['required', 'string', 'min:8', 'max:20'],
            'password' => ['required', 'string', 'min:8', 'max:72', 'confirmed'],
        ], $this->messages());

        $user = User::create([
            'name' => trim($data['name']),
            'email' => Str::lower(trim($data['email'])),
            'phone' => preg_replace('/\D+/', '', $data['phone']),
            'password' => $data['password'],
            'api_token' => Str::random(64),
        ]);

        return response()->json([
            'message' => 'Conta criada com sucesso!',
            'user' => $user,
            'token' => $user->api_token,
        ], 201);
    }

    /**
     * Autentica o usuario e devolve um token.
     */
    public function login(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => ['required', 'string', 'email', 'max:190'],
            'password' => ['required', 'string'],
        ], $this->messages());

        $user = User::where('email', Str::lower(trim($data['email'])))->first();

        if (! $user || ! Hash::check($data['password'], $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['E-mail ou senha invalidos.'],
            ]);
        }

        $user->forceFill(['api_token' => Str::random(64)])->save();

        return response()->json([
            'message' => 'Login realizado com sucesso!',
            'user' => $user,
            'token' => $user->api_token,
        ]);
    }

    /**
     * Retorna o usuario autenticado pelo token.
     */
    public function me(Request $request): JsonResponse
    {
        return response()->json(['user' => $request->user()]);
    }

    /**
     * Invalida o token atual.
     */
    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();
        $user->forceFill(['api_token' => null])->save();

        return response()->json(['message' => 'Sessao encerrada.']);
    }

    /**
     * @return array<string, string>
     */
    private function messages(): array
    {
        return [
            'name.required' => 'Informe o seu nome.',
            'name.min' => 'O nome precisa ter pelo menos 3 caracteres.',
            'email.required' => 'Informe o seu e-mail.',
            'email.email' => 'Informe um e-mail valido.',
            'email.unique' => 'Este e-mail ja esta cadastrado.',
            'phone.required' => 'Informe o seu telefone.',
            'phone.min' => 'Informe um telefone valido com DDD.',
            'password.required' => 'Informe uma senha.',
            'password.min' => 'A senha precisa ter pelo menos 8 caracteres.',
            'password.confirmed' => 'As senhas nao conferem.',
        ];
    }
}
