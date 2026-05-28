<?php

namespace sfsinfotech\craftmfaenforcer\controllers;

use Craft;
use craft\web\Controller;
use sfsinfotech\craftmfaenforcer\Plugin;
use yii\web\Response;

class SettingsController extends Controller
{
    public function init(): void
    {
        parent::init();
        $this->requireAdmin(false);
    }

    public function actionGeneral(): Response
    {
        return $this->renderTemplate('mfa-enforcer/general', [
            'settings' => Plugin::getInstance()->getSettings(),
        ]);
    }

    public function actionSaveGeneral(): ?Response
    {
        $this->requirePostRequest();
        $plugin = Plugin::getInstance();
        $settings = $plugin->getSettings();
        $request = Craft::$app->getRequest();

        $settings->enforcedGroupIds      = $request->getBodyParam('enforcedGroupIds', []) ?: [];
        $settings->exemptUserIds         = $request->getBodyParam('exemptUserIds', []) ?: [];
        $settings->failureLimit          = (int)$request->getBodyParam('failureLimit', 5);
        $settings->failureLockoutMinutes = (int)$request->getBodyParam('failureLockoutMinutes', 5);

        if (!$plugin->saveSettings($settings)) {
            Craft::$app->getSession()->setError(Craft::t('app', "Couldn't save settings."));
            return null;
        }

        Craft::$app->getSession()->setSuccess(Craft::t('app', 'Settings saved.'));
        return $this->redirectToPostedUrl();
    }

    public function actionProtectedActions(): Response
    {
        $settings = Plugin::getInstance()->getSettings();

        return $this->renderTemplate('mfa-enforcer/protected-actions', [
            'settings' => $settings,
            'sections' => Craft::$app->getEntries()->getAllSections(),
            'categoryGroups' => Craft::$app->getCategories()->getAllGroups(),
            'globalSets' => Craft::$app->getGlobals()->getAllSets(),
            'volumes' => Craft::$app->getVolumes()->getAllVolumes(),
        ]);
    }

    public function actionSaveProtectedActions(): ?Response
    {
        $this->requirePostRequest();

        $plugin = Plugin::getInstance();
        $settings = $plugin->getSettings();

        $postedActions = Craft::$app->getRequest()->getBodyParam('protectedActions', []);
        $normalised = [];
        if (is_array($postedActions)) {
            foreach ($postedActions as $key => $value) {
                if ($value) {
                    $normalised[$key] = true;
                }
            }
        }

        $settings->protectedActions = $normalised;

        if (!$plugin->saveSettings($settings)) {
            Craft::$app->getSession()->setError(Craft::t('app', 'Couldn\'t save settings.'));
            return null;
        }

        Craft::$app->getSession()->setSuccess(Craft::t('app', 'Settings saved.'));
        return $this->redirectToPostedUrl();
    }
}
