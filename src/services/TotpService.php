<?php

namespace sfsinfotech\craftmfaenforcer\services;

use Craft;
use craft\auth\methods\TOTP;
use craft\elements\User;
use yii\base\Component;

/**
 * Delegates TOTP verification to Craft 5's built-in Two-Step Verification.
 * Secrets are managed by Craft (craft_authenticators table) — this plugin
 * no longer maintains its own secret storage.
 */
class TotpService extends Component
{
    /**
     * Always true in Craft 5 — TOTP is a built-in auth method.
     */
    public function isAvailable(): bool
    {
        return true;
    }

    /**
     * Whether the user has Craft 5's built-in Authenticator App (TOTP) active.
     */
    public function isEnrolled(User $user): bool
    {
        try {
            return Craft::$app->getAuth()->getMethod(TOTP::class, $user)->isActive();
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Verify a TOTP code using Craft 5's built-in verification.
     * Includes replay prevention via Craft 5's timestamp tracking.
     */
    public function verifyCode(User $user, string $code): bool
    {
        $code = str_replace(' ', '', trim($code));
        if ($code === '') {
            return false;
        }

        try {
            return Craft::$app->getAuth()->getMethod(TOTP::class, $user)->verify($code);
        } catch (\Throwable) {
            return false;
        }
    }
}
