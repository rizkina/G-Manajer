<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\RateLimiter;

class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     */
    public function create(): View
    {
        return view('auth.login');
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request): RedirectResponse
    {
        $request->authenticate();

        $request->session()->regenerate();

        return redirect()->intended(route('dashboard', absolute: false));
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }

    public function authenticate(): void
    {
        $this->ensureIsNotRateLimited();

        // 1. Tentukan field untuk login (email atau nip_nisn)
        $loginField = filter_var($this->input('login'), FILTER_VALIDATE_EMAIL) ? 'email' : 'nip';

        // 2. Siapkan kredensial untuk percobaan login
        $credentials = [
            $loginField => $this->input('login'),
            'password' => $this->input('password'),
        ];

        // 3. Lakukan percobaan login dengan kredensial yang sudah disiapkan
        if (! Auth::attempt($credentials, $this->boolean('remember'))) {
            RateLimiter::hit($this->throttleKey());

            // 4. Jika gagal, kirim pesan error untuk field 'login'
            throw ValidationException::withMessages([
                'login' => trans('auth.failed'),
            ]);
        }

        RateLimiter::clear($this->throttleKey());
    }
}
