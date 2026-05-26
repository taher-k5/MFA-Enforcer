<?php

namespace sfsinfotech\craftmfaenforcer\services;

use Craft;
use craft\base\Element;

use craft\elements\Category;
use craft\elements\Entry;
use craft\elements\GlobalSet;
use craft\elements\User as UserElement;
use craft\events\ModelEvent;
use sfsinfotech\craftmfaenforcer\controllers\ChallengeController;
use sfsinfotech\craftmfaenforcer\Plugin;
use yii\base\ActionEvent;
use yii\base\Application;
use yii\base\Component;
use yii\base\Event;

class EventGuard extends Component
{
    public function registerEventListeners(): void
    {
        Event::on(Entry::class, Element::EVENT_BEFORE_SAVE, function (ModelEvent $event) {
            $entry = $event->sender;
            if ($this->skipForElement($entry)) {
                return;
            }
            // Craft sets firstSave = true immediately before EVENT_BEFORE_SAVE fires when
            // publishing a brand-new entry for the first time (the Drafts::removeDraftData
            // flow: draftId is cleared, firstSave is set to true, then saveElement() runs).
            // At that point getIsDraft() is already false and the entry has an existing id,
            // so the old `$entry->id ? 'save' : 'create'` test mis-classified it as a save.
            // Entry creation must never trigger MFA.
            if ($entry->firstSave) {
                return;
            }
            $this->challengeScoped($event, 'entry', $entry->sectionId, 'save');
        });

        Event::on(Entry::class, Element::EVENT_BEFORE_DELETE, function (ModelEvent $event) {
            $entry = $event->sender;
            if ($this->skipForElement($entry)) {
                return;
            }
            $this->challengeScoped($event, 'entry', $entry->sectionId, 'delete');
        });

        Event::on(GlobalSet::class, Element::EVENT_BEFORE_SAVE, function (ModelEvent $event) {
            $set = $event->sender;
            if ($this->skipForElement($set)) {
                return;
            }
            $this->challengeScoped($event, 'globalSet', $set->id, 'save');
        });


        Event::on(Category::class, Element::EVENT_BEFORE_SAVE, function (ModelEvent $event) {
            $cat = $event->sender;
            if ($this->skipForElement($cat)) {
                return;
            }

            // =====================================================
            // First category create in Craft 4 Never require MFA
            // =====================================================

            if ($cat->firstSave) {
                return;
            }

            $this->challengeScoped($event, 'category', $cat->groupId, 'save');
        });

        Event::on(Category::class, Element::EVENT_BEFORE_DELETE, function (ModelEvent $event) {
            $cat = $event->sender;
            if ($this->skipForElement($cat)) {
                return;
            }
            $this->challengeScoped($event, 'category', $cat->groupId, 'delete');
        });

        // ---- MFA Enforcer plugin settings saves ----
        // Protect our own settings controller so an enrolled user cannot change
        // enforcement rules or disable protections without first confirming MFA.
        // Un-enrolled users are allowed through — they can't be MFA-challenged yet.
        Event::on(Application::class, Application::EVENT_BEFORE_ACTION, function (ActionEvent $event) {
            try {
                $request = Craft::$app->getRequest();

                if ($request->getIsConsoleRequest() || !$request->getIsCpRequest() || !$request->getIsPost()) {
                    return;
                }

                $actionId = (string)($event->action->getUniqueId() ?? '');
                if (stripos($actionId, 'mfa-enforcer/settings/') !== 0) {
                    return;
                }

                $user = Craft::$app->getUser()->getIdentity();
                if ($user === null) {
                    return;
                }

                // Only require MFA for enrolled users — skip if not set up yet.
                if (!Plugin::getInstance()->totp->isEnrolled($user)) {
                    return;
                }

                $reason = $this->verifyOrReason();
                if ($reason === null) {
                    return;
                }

                // Block and surface the error to the browser.
                $event->isValid = false;
                if ($request->getIsAjax() || $request->getAcceptsJson()) {
                    Craft::$app->getResponse()->setStatusCode(401);
                    Craft::$app->getResponse()->data = ['error' => $reason];
                } else {
                    Craft::$app->getSession()->setError($reason);
                    Craft::$app->getResponse()->redirect($request->getReferrer() ?: '');
                    Craft::$app->end();
                }
            } catch (\Throwable $e) {
                // Best-effort only — never crash the CP.
            }
        });

        // ---- Utilities: Project Config actions (reapply, rebuild, download) ----
        Event::on(Application::class, Application::EVENT_BEFORE_ACTION, function (ActionEvent $event) {
            try {
                $request = Craft::$app->getRequest();

                if ($request->getIsConsoleRequest() || !$request->getIsCpRequest()) {
                    return;
                }

                $actionId = (string)($event->action->getUniqueId() ?? '');
                $settings = Plugin::getInstance()->getSettings();

                // Figure out which project-config action this is and whether it's protected
                $protectedKey = null;

                // config-sync with force=1 => reapply everything
                if (stripos($actionId, 'config-sync/') !== false) {
                    // Determine whether this is the "Reapply everything" flow (force=1)
                    $force = false;
                    $bodyForce = $request->getBodyParam('force');
                    if ($bodyForce !== null) {
                        $force = (bool)$bodyForce;
                    }
                    $params = $request->getBodyParam('params');
                    if (is_array($params) && array_key_exists('force', $params)) {
                        $force = (bool)$params['force'];
                    }
                    if (!$force) {
                        $qForce = $request->getQueryParam('force');
                        if ($qForce !== null) {
                            $force = (bool)$qForce;
                        }
                    }
                    if ($force) {
                        $protectedKey = 'utilities.projectConfig.reapply';
                    }
                }

                if ($protectedKey === null && stripos($actionId, 'project-config/rebuild') !== false) {
                    $protectedKey = 'utilities.projectConfig.rebuild';
                }

                if ($protectedKey === null && stripos($actionId, 'project-config/download') !== false) {
                    $protectedKey = 'utilities.projectConfig.download';
                }

                if ($protectedKey === null) {
                    return;
                }

                if (empty($settings->protectedActions) || empty($settings->protectedActions[$protectedKey] ?? null)) {
                    return;
                }

                if (!$this->audienceApplies()) {
                    return;
                }

                $reason = $this->verifyOrReason();
                // verifyOrReason returns null when verification succeeded
                if ($reason === null) {
                    return;
                }

                // Block the action and return an error response
                $event->isValid = false;
                if ($request->getIsAjax() || $request->getAcceptsJson()) {
                    Craft::$app->getResponse()->setStatusCode(401);
                    Craft::$app->getResponse()->data = ['error' => $reason];
                } else {
                    Craft::$app->getSession()->setError($reason);
                    Craft::$app->getResponse()->redirect($request->getReferrer() ?: '');
                    Craft::$app->end();
                }
            } catch (\Throwable $e) {
                // Best-effort only — don't crash the CP
            }
        });

        // ---- Utilities: Queue Manager actions (retry/release single & all) ----
        Event::on(Application::class, Application::EVENT_BEFORE_ACTION, function (ActionEvent $event) {
            try {
                $request = Craft::$app->getRequest();

                if ($request->getIsConsoleRequest() || !$request->getIsCpRequest()) {
                    return;
                }

                $actionId = (string)($event->action->getUniqueId() ?? '');
                $settings = Plugin::getInstance()->getSettings();

                $protectedKey = null;
                if (stripos($actionId, 'queue/retry') !== false) {
                    // covers retry and retry-all
                    $protectedKey = 'utilities.queueManager.retry';
                } elseif (stripos($actionId, 'queue/release') !== false) {
                    // covers release and release-all
                    $protectedKey = 'utilities.queueManager.release';
                }

                if ($protectedKey === null) {
                    return;
                }

                if (empty($settings->protectedActions) || empty($settings->protectedActions[$protectedKey] ?? null)) {
                    return;
                }

                if (!$this->audienceApplies()) {
                    return;
                }

                $reason = $this->verifyOrReason();
                if ($reason === null) {
                    return;
                }

                $event->isValid = false;
                if ($request->getIsAjax() || $request->getAcceptsJson()) {
                    Craft::$app->getResponse()->setStatusCode(401);
                    Craft::$app->getResponse()->data = ['error' => $reason];
                } else {
                    Craft::$app->getSession()->setError($reason);
                    Craft::$app->getResponse()->redirect($request->getReferrer() ?: '');
                    Craft::$app->end();
                }
            } catch (\Throwable $e) {
                // Best-effort only — don't crash the CP
            }
        });

        // ---- Utilities: Find and Replace ----
        Event::on(Application::class, Application::EVENT_BEFORE_ACTION, function (ActionEvent $event) {
            try {
                $request = Craft::$app->getRequest();

                if ($request->getIsConsoleRequest() || !$request->getIsCpRequest() || !$request->getIsPost()) {
                    return;
                }

                $actionId = (string)($event->action->getUniqueId() ?? '');
                if (stripos($actionId, 'find-and-replace-perform-action') === false) {
                    return;
                }

                $settings = Plugin::getInstance()->getSettings();
                if (empty($settings->protectedActions) || empty($settings->protectedActions['utilities.findAndReplace'] ?? null)) {
                    return;
                }

                if (!$this->audienceApplies()) {
                    return;
                }

                $reason = $this->verifyOrReason();
                if ($reason === null) {
                    return;
                }

                $event->isValid = false;
                if ($request->getIsAjax() || $request->getAcceptsJson()) {
                    Craft::$app->getResponse()->setStatusCode(401);
                    Craft::$app->getResponse()->data = ['error' => $reason];
                } else {
                    Craft::$app->getSession()->setError($reason);
                    Craft::$app->getResponse()->redirect($request->getReferrer() ?: '');
                    Craft::$app->end();
                }
            } catch (\Throwable $e) {
                // Best-effort only
            }
        });

    }

    private function skipForElement(?Element $element): bool
    {
        if ($element === null) {
            return true;
        }
        if ($element->propagating || $element->resaving) {
            return true;
        }
        if (method_exists($element, 'getIsDraft') && $element->getIsDraft()) {
            return true;
        }
        if (method_exists($element, 'getIsRevision') && $element->getIsRevision()) {
            return true;
        }
        return false;
    }

    /**
     * Shared preconditions for both scoped + simple challenges.
     * Returns true only when the *audience* should be challenged at all.
     */
    private function audienceApplies(): bool
    {
        $request = Craft::$app->getRequest();

        if ($request->getIsConsoleRequest()) {
            return false;
        }
        $user = Craft::$app->getUser()->getIdentity();
        if ($user === null) {
            return false;
        }
        if (!$request->getIsCpRequest()) {
            return false;
        }
        if (!Plugin::getInstance()->totp->isAvailable()) {
            return false;
        }
        $settings = Plugin::getInstance()->getSettings();
        if ($settings->isUserExempt((int)$user->id)) {
            return false;
        }
        $groupIds = array_map(fn($g) => (int)$g->id, $user->getGroups());
        if (!$settings->userInEnforcedGroup($groupIds)) {
            return false;
        }
        return true;
    }

    private function shouldChallengeScoped(string $type, ?int $resourceId, string $op): bool
    {
        if (!$this->audienceApplies()) {
            return false;
        }
        return Plugin::getInstance()->getSettings()->isScopedActionProtected($type, $resourceId, $op);
    }

    private function challengeScoped(ModelEvent $event, string $type, ?int $resourceId, string $op): void
    {
        if (!$this->shouldChallengeScoped($type, $resourceId, $op)) {
            return;
        }
        $reason = $this->verifyOrReason();
        if ($reason === null) {
            return;
        }
        $event->isValid = false;
        $element = $event->sender;
        if ($element instanceof Element) {
            $element->addError('mfaEnforcer', $reason);
        }
    }

    /**
     * Tracks the token already consumed in this request so bulk operations
     * (multiple EVENT_BEFORE_DELETE in one HTTP request) don't re-consume it.
     */
    private static ?string $verifiedTokenThisRequest = null;

    /**
     * Returns null when verification succeeds; otherwise a human-readable reason.
     */
    private function verifyOrReason(): ?string
    {
        $user = Craft::$app->getUser()->getIdentity();
        $plugin = Plugin::getInstance();

        if (!$plugin->totp->isEnrolled($user)) {
            return 'This action requires two-factor authentication, but your account is not enrolled. Please set up MFA via MFA Enforcer → My MFA before retrying.';
        }


        $request = Craft::$app->getRequest();
        $headerToken = $request->getHeaders()->get('X-Mfa-Enforcer-Token');
        $bodyToken = $request->getBodyParam('mfaEnforcerToken', '');
        $queryToken = $request->getQueryParam('mfaEnforcerToken');
        $token = (string)($headerToken ?: $bodyToken ?: $queryToken);
        if ($token === '') {
            return 'MFA confirmation is required for this action.';
        }

        // Bulk operations (e.g. bulk delete) fire EVENT_BEFORE_DELETE once per element
        // within a single HTTP request. The token is consumed on the first event, so
        // subsequent events would fail. Cache the verified token for the request lifetime.
        if (self::$verifiedTokenThisRequest === $token) {
            return null;
        }

        $consumed = $plugin->tokens->consume($token, (int)$user->id);
        if (!$consumed) {
            return 'MFA confirmation expired or already used. Please retry and confirm again.';
        }

        self::$verifiedTokenThisRequest = $token;
        return null;
    }
}
