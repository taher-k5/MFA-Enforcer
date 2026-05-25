<?php

namespace sfsinfotech\craftmfaenforcer\services;

use Craft;
use born05\twofactorauthentication\Plugin as TwoFactorAuth;
use craft\elements\User;
use yii\base\Component;

class TotpService extends Component
{
    /**
     * Whether the underlying TOTP backend (born05/craft-twofactorauthentication)
     * is installed AND enabled. When false, MFA challenges should bypass entirely
     * — the host environment has opted out of 2FA (e.g. via `disabledPlugins` in
     * config/general.php for local/dev).
     */
    public function isAvailable(): bool
    {
        return Craft::$app->getPlugins()->isPluginEnabled('two-factor-authentication')
            && TwoFactorAuth::getInstance() !== null;
    }

    public function isEnrolled(User $user): bool
    {
        if (!$this->isAvailable()) {
            return false;
        }
        return (bool)TwoFactorAuth::getInstance()->verify->isEnabled($user);
    }

    public function verifyCode(User $user, string $code): bool
    {
        if (!$this->isAvailable()) {
            return false;
        }
        return (bool)TwoFactorAuth::getInstance()->verify->verify($user, $code);
    }
}
