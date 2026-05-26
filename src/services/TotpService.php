<?php

namespace sfsinfotech\craftmfaenforcer\services;

use Craft;
use craft\elements\User;
use OTPHP\TOTP;
use sfsinfotech\craftmfaenforcer\records\UserSecretRecord;
use yii\base\Component;

/**
 * Self-contained TOTP service using spomky-labs/otphp.
 * No external plugin dependency — secrets are stored in {{%mfaenforcer_user_secrets}}.
 */
class TotpService extends Component
{
    /**
     * Always true: the library is bundled, no external plugin required.
     */
    public function isAvailable(): bool
    {
        return true;
    }

    /**
     * Whether the user has completed TOTP setup (secret verified and enabled).
     */
    public function isEnrolled(User $user): bool
    {
        $record = UserSecretRecord::findOne(['userId' => $user->id]);
        return $record !== null && (bool)$record->enabled;
    }

    /**
     * Get the existing secret record or create a new one with a fresh random secret.
     */
    public function getOrCreateRecord(User $user): UserSecretRecord
    {
        $record = UserSecretRecord::findOne(['userId' => $user->id]);
        if ($record === null) {
            $totp = TOTP::generate();
            $record = new UserSecretRecord();
            $record->userId  = $user->id;
            $record->secret  = $totp->getSecret();
            $record->enabled = false;
            $record->save(false);
        }
        return $record;
    }

    /**
     * Generate a fresh secret for the user (resets any existing secret and marks as not enrolled).
     */
    public function regenerateSecret(User $user): UserSecretRecord
    {
        $totp    = TOTP::generate();
        $record  = $this->getOrCreateRecord($user);
        $record->secret  = $totp->getSecret();
        $record->enabled = false;
        $record->save(false);
        return $record;
    }

    /**
     * Return the raw Base32 secret for manual entry into an authenticator app.
     */
    public function getUserSecret(User $user): string
    {
        return $this->getOrCreateRecord($user)->secret;
    }

    /**
     * Return the otpauth:// URI for QR code generation.
     */
    public function getProvisioningUri(User $user): string
    {
        $record = $this->getOrCreateRecord($user);
        $totp   = TOTP::createFromSecret($record->secret);
        $totp->setLabel($user->email ?? (string)$user->id);
        $totp->setIssuer(Craft::$app->getSystemName());
        return $totp->getProvisioningUri();
    }

    /**
     * Verify a TOTP code for the given user.
     * Includes ±1 window of clock-drift tolerance and replay prevention via Craft cache.
     */
    public function verifyCode(User $user, string $code): bool
    {
        $record = UserSecretRecord::findOne(['userId' => $user->id]);
        if ($record === null) {
            return false;
        }

        $code = str_replace(' ', '', trim($code));

        // Replay prevention: a code can only be used once within its 30-second window.
        $replayCacheKey = "mfaEnforcer.usedCode.{$user->id}.{$code}";
        if (Craft::$app->getCache()->get($replayCacheKey)) {
            return false;
        }

        $totp = TOTP::createFromSecret($record->secret);
        $totp->setLabel($user->email ?? (string)$user->id);
        $totp->setIssuer(Craft::$app->getSystemName());

        // Allow ±1 window of clock drift (±30 seconds).
        $isValid = $totp->verify($code, null, 1);

        if ($isValid) {
            // Mark this code as used for 31 seconds (TOTP period + 1s safety buffer).
            Craft::$app->getCache()->set($replayCacheKey, true, 31);
        }

        return $isValid;
    }

    /**
     * Mark the user as fully enrolled (called after first successful code verification).
     */
    public function enableForUser(User $user): bool
    {
        $record = UserSecretRecord::findOne(['userId' => $user->id]);
        if ($record === null) {
            return false;
        }
        $record->enabled = true;
        return (bool)$record->save(false);
    }

    /**
     * Revoke TOTP for the user (marks as not enrolled; secret is preserved for re-enrolment).
     */
    public function disableForUser(User $user): bool
    {
        $record = UserSecretRecord::findOne(['userId' => $user->id]);
        if ($record === null) {
            return false;
        }
        $record->enabled = false;
        return (bool)$record->save(false);
    }
}
