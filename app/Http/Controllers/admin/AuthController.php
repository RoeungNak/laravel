<?php

namespace App\Http\Controllers\admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function authenticate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 400,
                'errors' => $validator->errors()
            ], 400);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => 401,
                'message' => 'Invalid email or password.'
            ], 401);
        }

        if ($user->role !== 'admin') {
            return response()->json([
                'status' => 403,
                'message' => 'You are not admin.'
            ], 403);
        }

        // ✅ Create API token (Sanctum)
        $token = $user->createToken('admin-token')->plainTextToken;

        return response()->json([
            'status' => 200,
            'token' => $token,
            'id' => $user->id,
            'name' => $user->name,
        ], 200);
    }
}
