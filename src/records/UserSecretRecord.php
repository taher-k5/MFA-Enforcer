<?php

namespace sfsinfotech\craftmfaenforcer\records;

use craft\db\ActiveRecord;

/**
 * @property int    $id
 * @property int    $userId
 * @property string $secret   Base32-encoded TOTP secret
 * @property bool   $enabled  Whether the user has completed setup verification
 * @property string $dateCreated
 * @property string $dateUpdated
 * @property string $uid
 */
class UserSecretRecord extends ActiveRecord
{
    public static function tableName(): string
    {
        return '{{%mfaenforcer_user_secrets}}';
    }
}
