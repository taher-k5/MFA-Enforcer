<?php

namespace sfsinfotech\craftmfaenforcer\services;

use Craft;
use craft\helpers\DateTimeHelper;
use craft\helpers\Db;
use craft\helpers\StringHelper;
use DateTime;
use sfsinfotech\craftmfaenforcer\Plugin;
use sfsinfotech\craftmfaenforcer\records\MfaEnforcerTokenRecord;
use yii\base\Component;

class TokenService extends Component
{
    public function issue(int $userId, string $actionKey): string
    {
        $token = StringHelper::randomString(48);
        $ttl = 30;
        $expiresAt = (new DateTime())->modify("+{$ttl} seconds");

        $record = new MfaEnforcerTokenRecord();
        $record->userId = $userId;
        $record->token = $token;
        $record->actionKey = $actionKey;
        $record->expiresAt = Db::prepareDateForDb($expiresAt);
        $record->save(false);

        return $token;
    }

    /**
     * Consume a token. Returns true only once per token; subsequent calls return false.
     * Token is scoped to the user only — Craft's CP saves through generic AJAX endpoints
     * (e.g. `elements/apply-draft`) where the JS interceptor can't know the eventual
     * element type, so per-action scoping would break legitimate saves.
     */
    public function consume(string $token, int $userId): bool
    {
        $record = MfaEnforcerTokenRecord::findOne([
            'token' => $token,
            'userId' => $userId,
        ]);

        if ($record === null || $record->usedAt !== null) {
            return false;
        }

        $now = DateTimeHelper::currentUTCDateTime();
        if (DateTimeHelper::toDateTime($record->expiresAt) < $now) {
            return false;
        }

        $record->usedAt = Db::prepareValueForDb($now);
        $record->save(false);

        return true;
    }

    /**
     * Verify a token is valid without consuming it.
     * Used for multi-file upload batches where one MFA confirmation
     * should cover all files uploaded within the token's TTL window.
     */
    public function verify(string $token, int $userId): bool
    {
        $record = MfaEnforcerTokenRecord::findOne([
            'token'  => $token,
            'userId' => $userId,
        ]);

        if ($record === null) {
            return false;
        }

        $now = DateTimeHelper::currentUTCDateTime();
        if (DateTimeHelper::toDateTime($record->expiresAt) < $now) {
            return false;
        }

        return true;
    }

    public function purgeExpired(): void
    {
        Craft::$app->getDb()->createCommand()
            ->delete('{{%mfaenforcer_tokens}}', ['<', 'expiresAt', Db::prepareDateForDb(new DateTime('-1 day'))])
            ->execute();
    }
}
