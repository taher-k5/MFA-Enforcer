<?php

namespace sfsinfotech\craftmfaenforcer;

use Craft;
use craft\base\Plugin as BasePlugin;
use craft\db\Query;
use craft\db\Table;
use craft\events\RegisterTemplateRootsEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\web\UrlManager;
use craft\web\View;
use sfsinfotech\craftmfaenforcer\models\Settings;
use sfsinfotech\craftmfaenforcer\records\SettingsRecord;
use sfsinfotech\craftmfaenforcer\services\EventGuard;
use sfsinfotech\craftmfaenforcer\services\TokenService;
use sfsinfotech\craftmfaenforcer\services\TotpService;
use sfsinfotech\craftmfaenforcer\web\assets\cp\CpAsset;
use yii\base\Event;

/**
 * @property-read EventGuard $guard
 * @property-read TokenService $tokens
 * @property-read TotpService $totp
 * @property-read Settings $settings
 * @method Settings getSettings()
 * @method static Plugin getInstance()
 */
class Plugin extends BasePlugin
{
    public static Plugin $plugin;

    public string $schemaVersion = '1.0.0';
    public bool $hasCpSettings = false;
    public bool $hasCpSection = true;

    private ?Settings $_dbSettings = null;

    public function init(): void
    {
        parent::init();
        self::$plugin = $this;

        Craft::setAlias('@sfsinfotech/craftmfaenforcer', __DIR__);

        $this->controllerNamespace = Craft::$app->getRequest()->getIsConsoleRequest()
            ? 'sfsinfotech\\craftmfaenforcer\\console\\controllers'
            : 'sfsinfotech\\craftmfaenforcer\\controllers';

        $this->setComponents([
            'guard' => EventGuard::class,
            'tokens' => TokenService::class,
            'totp' => TotpService::class,
        ]);

        Event::on(
            View::class,
            View::EVENT_REGISTER_CP_TEMPLATE_ROOTS,
            function (RegisterTemplateRootsEvent $event) {
                $event->roots['mfa-enforcer'] = __DIR__ . '/templates';
            }
        );

        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            function (RegisterUrlRulesEvent $event) {
                $event->rules['mfa-enforcer'] = 'mfa-enforcer/settings/protected-actions';
                $event->rules['mfa-enforcer/general'] = 'mfa-enforcer/settings/general';
                $event->rules['mfa-enforcer/protected-actions'] = 'mfa-enforcer/settings/protected-actions';
                $event->rules['POST mfa-enforcer/general/save'] = 'mfa-enforcer/settings/save-general';
                $event->rules['POST mfa-enforcer/protected-actions/save'] = 'mfa-enforcer/settings/save-protected-actions';
                $event->rules['mfa-enforcer/setup'] = 'mfa-enforcer/setup/index';
                $event->rules['POST mfa-enforcer/setup/enable'] = 'mfa-enforcer/setup/enable';
                $event->rules['POST mfa-enforcer/setup/disable'] = 'mfa-enforcer/setup/disable';
                $event->rules['POST mfa-enforcer/setup/refresh-secret'] = 'mfa-enforcer/setup/refresh-secret';
                $event->rules['POST mfa-enforcer/setup/admin-reset'] = 'mfa-enforcer/setup/admin-reset';
            }
        );

        if (Craft::$app->getRequest()->getIsCpRequest()) {
            $this->registerCpAsset();
        }

        $this->guard->registerEventListeners();
    }

    protected function createSettingsModel(): ?\craft\base\Model
    {
        return new Settings();
    }

    /**
     * Load settings from the database (not from project config).
     */
    public function getSettings(): Settings
    {
        if ($this->_dbSettings !== null) {
            return $this->_dbSettings;
        }

        $settings = new Settings();

        try {
            /** @var SettingsRecord|null $record */
            $record = SettingsRecord::find()->one();
            if ($record !== null) {
                $settings->enforcedGroupIds      = json_decode($record->enforcedGroupIds, true) ?? [];
                $settings->exemptUserIds         = json_decode($record->exemptUserIds, true) ?? [];
                $settings->failureLimit          = (int)$record->failureLimit;
                $settings->failureLockoutMinutes = (int)$record->failureLockoutMinutes;
                $settings->protectedActions      = json_decode($record->protectedActions, true) ?? [];
            }
        } catch (\Throwable $e) {
            // Table may not exist yet during the first migration run.
            Craft::warning('MfaEnforcer: could not load settings from DB: ' . $e->getMessage(), __METHOD__);
        }

        $this->_dbSettings = $settings;
        return $settings;
    }

    /**
     * Craft calls this with values from project config — intentionally ignored
     * because settings are stored in our own DB table, not in project config.
     */
    public function setSettings(array $values): void
    {
        // no-op: DB is the source of truth.
    }

    /**
     * Persist settings to the database.
     */
    public function saveSettings(Settings $settings): bool
    {
        try {
            /** @var SettingsRecord|null $record */
            $record = SettingsRecord::find()->one();
            if ($record === null) {
                $record = new SettingsRecord();
            }

            $record->enforcedGroupIds      = json_encode(array_values(array_filter(array_map('intval', $settings->enforcedGroupIds ?: []))));
            $record->exemptUserIds         = json_encode(array_values(array_filter(array_map('intval', $settings->exemptUserIds ?: []))));
            $record->failureLimit          = max(1, (int)$settings->failureLimit);
            $record->failureLockoutMinutes = max(1, (int)$settings->failureLockoutMinutes);
            $record->protectedActions      = json_encode($settings->protectedActions ?: []);

            if (!$record->save(false)) {
                return false;
            }

            $this->_dbSettings = $settings;
            return true;
        } catch (\Throwable $e) {
            Craft::error('MfaEnforcer: could not save settings: ' . $e->getMessage(), __METHOD__);
            return false;
        }
    }

    public function getCpNavItem(): ?array
    {
        $item = parent::getCpNavItem();
        $item['label'] = 'MFA enforcer';
        $item['url'] = 'mfa-enforcer';
        $item['subnav'] = [
            'protected-actions' => ['label' => 'Protected Actions', 'url' => 'mfa-enforcer/protected-actions'],
            'setup' => ['label' => 'My MFA', 'url' => 'mfa-enforcer/setup'],
            'general' => ['label' => 'Settings', 'url' => 'mfa-enforcer/general'],
        ];
        return $item;
    }

    /**
     * Inspect the current CP request path and figure out which protected resource (if any)
     * the user is currently editing. Returns null when the page is not a single-resource
     * edit page (e.g. on a dashboard, listing screen, or unrelated CP page).
     *
    * Shape: ['type' => 'entry|category|globalSet', 'id' => int]
     */
    private function detectCurrentResourceContext(): ?array
    {
        try {
            $path = trim((string)Craft::$app->getRequest()->getPathInfo(), '/');
            if ($path === '') {
                return null;
            }

            // /entries/{section-handle}/...
            if (preg_match('#^entries/([^/]+)#', $path, $m)) {
                $section = Craft::$app->getSections()->getSectionByHandle($m[1]);
                if ($section !== null) {
                    return ['type' => 'entry', 'id' => (int)$section->id];
                }
            }

            // /categories/{group-handle}/...
            if (preg_match('#^categories/([^/]+)#', $path, $m)) {
                $group = Craft::$app->getCategories()->getGroupByHandle($m[1]);
                if ($group !== null) {
                    return ['type' => 'category', 'id' => (int)$group->id];
                }
            }

            // /globals/{set-handle}
            if (preg_match('#^globals/([^/]+)#', $path, $m)) {
                $set = Craft::$app->getGlobals()->getSetByHandle($m[1]);
                if ($set !== null) {
                    return ['type' => 'globalSet', 'id' => (int)$set->id];
                }
            }

            // /assets/{volume-handle}/...
            if (preg_match('#^assets/([^/]+)#', $path, $m)) {
                $volume = Craft::$app->getVolumes()->getVolumeByHandle($m[1]);
                if ($volume !== null) {
                    return ['type' => 'asset', 'id' => (int)$volume->id];
                }
            }
        } catch (\Throwable $e) {
            // Best-effort detection only — never block CP rendering.
        }

        return null;
    }

    private function registerCpAsset(): void
    {
        Event::on(
            View::class,
            View::EVENT_BEFORE_RENDER_TEMPLATE,
            function () {
                $user = Craft::$app->getUser()->getIdentity();
                if ($user === null) {
                    return;
                }
                $view = Craft::$app->getView();
                $view->registerAssetBundle(CpAsset::class);

                $settings = $this->getSettings();
                $userGroupIds = array_map(fn($g) => (int)$g->id, $user->getGroups());
                $applies = $settings->userInEnforcedGroup($userGroupIds)
                    && !$settings->isUserExempt((int)$user->id)
                    && $this->totp->isAvailable();

                // Detect if the current CP page is editing a brand-new (unpublished) entry
                // draft. Unpublished drafts have NULL canonicalId in the drafts table because
                // the draft itself is the canonical element. This flag is passed to the JS
                // interceptor so it can skip the MFA modal for new-entry creation flows.
                $isUnpublishedDraft = false;
                $draftId = (int)(Craft::$app->getRequest()->getParam('draftId') ?? 0);
                if ($draftId > 0) {
                    try {
                        // A NULL canonicalId means this draft has no separate canonical —
                        // it IS the canonical (i.e. an unpublished / fresh new entry).
                        $canonicalId = (new Query())
                            ->select(['canonicalId'])
                            ->from([Table::DRAFTS])
                            ->where(['id' => $draftId])
                            ->scalar();
                        $isUnpublishedDraft = ($canonicalId === null || $canonicalId === false);
                    } catch (\Throwable $e) {
                        // Table may not exist yet; leave flag false.
                    }
                }

                // Detect the current resource context (section / category group / global set)
                // from the CP URL so the JS interceptor can do a SECTION-SPECIFIC
                // protection check rather than falling back to "match any of this resource type"
                // (which is why protecting one section appeared to apply to all sections).
                $currentResourceContext = $this->detectCurrentResourceContext();

                // Build a source-key → {type, id} map for every protected resource so the
                // JS interceptor can resolve the element-indexes/perform-action 'source'
                // body param (format: 'section:{uid}' / 'group:{uid}') to a numeric ID.
                // This is critical when the page loaded at a generic URL (e.g. /entries
                // without a section path component) so currentResourceContext is null —
                // which happens on every Craft CP PJAX navigation from another page.
                $sourceKeyMap = [];
                if ($applies) {
                    try {
                        foreach ($settings->protectedActions as $actionKey => $value) {
                            if (!$value) {
                                continue;
                            }
                            if (preg_match('/^entry\.(\d+)\./', $actionKey, $m)) {
                                $section = Craft::$app->getSections()->getSectionById((int)$m[1]);
                                if ($section !== null) {
                                    $sourceKeyMap['section:' . $section->uid] = ['type' => 'entry', 'id' => (int)$m[1], 'name' => $section->name];
                                }
                            } elseif (preg_match('/^category\.(\d+)\./', $actionKey, $m)) {
                                $group = Craft::$app->getCategories()->getGroupById((int)$m[1]);
                                if ($group !== null) {
                                    $sourceKeyMap['group:' . $group->uid] = ['type' => 'category', 'id' => (int)$m[1], 'name' => $group->name];
                                }
                            } elseif (preg_match('/^asset\.(\d+)\./', $actionKey, $m)) {
                                $volume = Craft::$app->getVolumes()->getVolumeById((int)$m[1]);
                                if ($volume !== null) {
                                    $sourceKeyMap['volume:' . $volume->uid] = ['type' => 'asset', 'id' => (int)$m[1]];
                                }
                            }
                        }
                    } catch (\Throwable $e) {
                        // Best-effort only — never block CP rendering.
                    }
                }

                // Build a folderId → volumeId map for all protected-upload volumes.
                // assets/upload requests carry folderId (not volumeId) in the body, so the
                // JS interceptor uses this map to resolve which volume an upload targets.
                $folderVolumeMap = [];
                if ($applies) {
                    try {
                        foreach ($settings->protectedActions as $actionKey => $value) {
                            if (!$value) {
                                continue;
                            }
                            if (preg_match('/^asset\.(\d+)\.upload$/', $actionKey, $m)) {
                                $volumeId = (int)$m[1];
                                $folderIds = (new \craft\db\Query())
                                    ->select(['id'])
                                    ->from(['{{%volumefolders}}'])
                                    ->where(['volumeId' => $volumeId])
                                    ->column();
                                foreach ($folderIds as $folderId) {
                                    $folderVolumeMap[(string)$folderId] = $volumeId;
                                }
                            }
                        }
                    } catch (\Throwable $e) {
                        // Best-effort only — never block CP rendering.
                    }
                }

                $config = [
                    'verifyUrl' => '/' . trim(Craft::$app->getConfig()->getGeneral()->cpTrigger, '/') . '/actions/mfa-enforcer/challenge/verify',
                    'csrfTokenName' => Craft::$app->getRequest()->csrfParam,
                    'csrfToken' => Craft::$app->getRequest()->getCsrfToken(),
                    'applies' => $applies,
                    // true when the current user has set up and enabled MFA for their account.
                    // The JS uses this to gate the settings-save modal independently of the
                    // group-level `applies` flag and the `protectedActions` config.
                    'userEnrolled' => $this->totp->isEnrolled($user),
                    'setupUrl' => \craft\helpers\UrlHelper::cpUrl('mfa-enforcer/setup'),
                    'protectedActions' => $applies ? $settings->protectedActions : [],
                    'isUnpublishedDraft' => $isUnpublishedDraft,
                    'currentResourceContext' => $currentResourceContext,
                    'sourceKeyMap' => $sourceKeyMap,
                    'folderVolumeMap' => $folderVolumeMap,
                ];
                $view->registerJs('window.MfaEnforcerConfig = ' . json_encode($config) . ';', $view::POS_HEAD);
            }
        );
    }
}
