<?php

namespace modules\actionmfa\records;

use craft\db\ActiveRecord;

/**
 * @property int $id
 * @property int $userId
 * @property string $token
 * @property string $actionKey
 * @property string $expiresAt
 * @property string|null $usedAt
 */
class ActionMfaTokenRecord extends ActiveRecord
{
    public static function tableName(): string
    {
        return '{{%actionmfa_tokens}}';
    }
}
