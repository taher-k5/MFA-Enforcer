<?php

namespace sfsinfotech\craftmfaenforcer\controllers;

use Craft;
use craft\helpers\UrlHelper;
use craft\web\Controller;
use sfsinfotech\craftmfaenforcer\Plugin;
use yii\web\Response;

/**
 * Handles per-user TOTP setup: generate secret, display QR code,
 * verify first code to enable MFA, disable MFA.
 *
 * Any logged-in CP user can access their own setup page.
 * Admin-level reset is available via actionAdminReset (POST JSON).
 */
class SetupController extends Controller
{
    protected array|int|bool $allowAnonymous = false;

    // -------------------------------------------------------------------------
    // GET  /admin/mfa-enforcer/setup
    // -------------------------------------------------------------------------
    public function actionIndex(): Response
    {
        $this->requireLogin();

        $user   = Craft::$app->getUser()->getIdentity();
        $plugin = Plugin::getInstance();

        $isEnrolled     = $plugin->totp->isEnrolled($user);
        $provisioningUri = null;
        $secret          = null;

        if (!$isEnrolled) {
            // Pre-create the secret row so the QR code is stable on refresh.
            $provisioningUri = $plugin->totp->getProvisioningUri($user);
            $secret          = $plugin->totp->getUserSecret($user);
        }

        return $this->renderTemplate('mfa-enforcer/setup', [
            'isEnrolled'      => $isEnrolled,
            'provisioningUri' => $provisioningUri,
            'secret'          => $secret,
        ]);
    }

    // -------------------------------------------------------------------------
    // POST /admin/actions/mfa-enforcer/setup/refresh-secret  (JSON)
    // Generates a new secret and returns the new provisioning URI.
    // Used by the "Generate new secret" button before the user enables MFA.
    // -------------------------------------------------------------------------
    public function actionRefreshSecret(): Response
    {
        $this->requirePostRequest();
        $this->requireLogin();
        $this->requireAcceptsJson();

        $user   = Craft::$app->getUser()->getIdentity();
        $plugin = Plugin::getInstance();

        // Block rotation if already enrolled (user must disable first).
        if ($plugin->totp->isEnrolled($user)) {
            return $this->asJson([
                'success' => false,
                'error'   => 'MFA is already enabled. Disable it first before generating a new secret.',
            ])->setStatusCode(409);
        }

        $record          = $plugin->totp->regenerateSecret($user);
        $provisioningUri = $plugin->totp->getProvisioningUri($user);

        return $this->asJson([
            'success'        => true,
            'secret'         => $record->secret,
            'provisioningUri' => $provisioningUri,
        ]);
    }

    // -------------------------------------------------------------------------
    // POST /admin/actions/mfa-enforcer/setup/enable
    // Verify the first TOTP code and mark the user as enrolled.
    // -------------------------------------------------------------------------
    public function actionEnable(): Response
    {
        $this->requirePostRequest();
        $this->requireLogin();

        $user   = Craft::$app->getUser()->getIdentity();
        $plugin = Plugin::getInstance();
        $code   = trim((string)Craft::$app->getRequest()->getBodyParam('code', ''));

        if ($code === '') {
            Craft::$app->getSession()->setError(Craft::t('app', 'Please enter your authentication code.'));
            return $this->redirectToPostedUrl();
        }

        if (!$plugin->totp->verifyCode($user, $code)) {
            Craft::$app->getSession()->setError(
                Craft::t('app', 'Invalid authentication code. Please try again.')
            );
            return $this->redirectToPostedUrl();
        }

        $plugin->totp->enableForUser($user);

        // Immediately set the session window so the user does not need to
        // re-verify for the next 10 minutes.
        $this->setSessionWindow($user->id);

        Craft::$app->getSession()->setSuccess(
            Craft::t('app', 'Two-factor authentication has been enabled.')
        );
        return $this->redirectToPostedUrl();
    }

    // -------------------------------------------------------------------------
    // POST /admin/actions/mfa-enforcer/setup/disable
    // User must enter their current TOTP code to confirm disabling MFA.
    // -------------------------------------------------------------------------
    public function actionDisable(): Response
    {
        $this->requirePostRequest();
        $this->requireLogin();

        $user   = Craft::$app->getUser()->getIdentity();
        $plugin = Plugin::getInstance();
        $code   = trim((string)Craft::$app->getRequest()->getBodyParam('code', ''));

        if ($code === '') {
            Craft::$app->getSession()->setError(
                Craft::t('app', 'Please enter your current authentication code to disable MFA.')
            );
            return $this->redirectToPostedUrl();
        }

        if (!$plugin->totp->verifyCode($user, $code)) {
            Craft::$app->getSession()->setError(
                Craft::t('app', 'Invalid authentication code. MFA was not disabled.')
            );
            return $this->redirectToPostedUrl();
        }

        $plugin->totp->disableForUser($user);

        // Clear the session window when MFA is disabled.
        Craft::$app->getSession()->remove(ChallengeController::SESSION_WINDOW_KEY_PREFIX . $user->id);

        Craft::$app->getSession()->setNotice(
            Craft::t('app', 'Two-factor authentication has been disabled.')
        );
        return $this->redirectToPostedUrl();
    }

    // -------------------------------------------------------------------------
    // POST /admin/actions/mfa-enforcer/setup/admin-reset  (JSON, admin only)
    // Admin resets another user's MFA enrollment without requiring their code.
    // -------------------------------------------------------------------------
    public function actionAdminReset(): Response
    {
        $this->requirePostRequest();
        $this->requireAdmin();
        $this->requireAcceptsJson();

        $userId = (int)Craft::$app->getRequest()->getRequiredBodyParam('userId');
        $user   = Craft::$app->getUsers()->getUserById($userId);

        if ($user === null) {
            return $this->asJson(['success' => false, 'error' => 'User not found.'])->setStatusCode(404);
        }

        Plugin::getInstance()->totp->disableForUser($user);

        // Clear their session window too.
        Craft::$app->getSession()->remove(ChallengeController::SESSION_WINDOW_KEY_PREFIX . $userId);

        return $this->asJson(['success' => true]);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------
    private function setSessionWindow(int $userId): void
    {
        $key = ChallengeController::SESSION_WINDOW_KEY_PREFIX . $userId;
        Craft::$app->getSession()->set($key, time() + ChallengeController::SESSION_WINDOW_SECONDS);
    }
}
