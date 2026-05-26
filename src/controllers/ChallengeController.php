<?php

namespace sfsinfotech\craftmfaenforcer\controllers;

use Craft;
use craft\web\Controller;
use sfsinfotech\craftmfaenforcer\Plugin;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\Response;

class ChallengeController extends Controller
{
    protected array|int|bool $allowAnonymous = false;

    /**
     * Craft session key prefix for the 10-minute MFA verification window.
     * The full key is SESSION_WINDOW_KEY_PREFIX . $userId.
     */
    public const SESSION_WINDOW_KEY_PREFIX = 'mfaEnforcer.verified.';

    /**
     * Duration (seconds) that a successful TOTP verification remains trusted.
     */
    public const SESSION_WINDOW_SECONDS = 600; // 10 minutes

    public function actionVerify(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();

        $user = Craft::$app->getUser()->getIdentity();
        if ($user === null) {
            throw new ForbiddenHttpException();
        }

        $request   = Craft::$app->getRequest();
        $code      = trim((string)$request->getBodyParam('code', ''));
        $actionKey = (string)$request->getBodyParam('actionKey', 'universal');

        if ($code === '') {
            throw new BadRequestHttpException('Missing code.');
        }

        $plugin = Plugin::getInstance();

        if ($this->isLockedOut($user->id)) {
            return $this->asJson([
                'success' => false,
                'error'   => 'Too many failed attempts. Try again later.',
            ])->setStatusCode(429);
        }

        if (!$plugin->totp->isEnrolled($user)) {
            return $this->asJson([
                'success'  => false,
                'error'    => 'Your account is not enrolled in two-factor authentication.',
                'enrolUrl' => \craft\helpers\UrlHelper::cpUrl('mfa-enforcer/setup'),
            ])->setStatusCode(409);
        }

        if (!$plugin->totp->verifyCode($user, $code)) {
            $this->recordFailure($user->id);
            return $this->asJson([
                'success' => false,
                'error'   => 'Invalid code. Please try again.',
            ])->setStatusCode(401);
        }

        $this->clearFailures($user->id);

        // Set a 10-minute session window so the user doesn't need to re-verify soon.
        $sessionKey = self::SESSION_WINDOW_KEY_PREFIX . $user->id;
        Craft::$app->getSession()->set($sessionKey, time() + self::SESSION_WINDOW_SECONDS);

        $token = $plugin->tokens->issue($user->id, $actionKey);

        return $this->asJson([
            'success'              => true,
            'token'                => $token,
            'sessionWindowSeconds' => self::SESSION_WINDOW_SECONDS,
        ]);
    }

    private function failureCacheKey(int $userId): string
    {
        return "mfaEnforcer.failures.{$userId}";
    }

    private function isLockedOut(int $userId): bool
    {
        $settings = Plugin::getInstance()->getSettings();
        $count    = (int)Craft::$app->getCache()->get($this->failureCacheKey($userId));
        return $count >= $settings->failureLimit;
    }

    private function recordFailure(int $userId): void
    {
        $settings = Plugin::getInstance()->getSettings();
        $cache    = Craft::$app->getCache();
        $key      = $this->failureCacheKey($userId);
        $count    = (int)$cache->get($key);
        $cache->set($key, $count + 1, $settings->failureLockoutMinutes * 60);
    }

    private function clearFailures(int $userId): void
    {
        Craft::$app->getCache()->delete($this->failureCacheKey($userId));
    }
}
