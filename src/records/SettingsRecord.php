<?php

namespace sfsinfotech\craftmfaenforcer\records;

use craft\db\ActiveRecord;

/**
 * @property int    $id
 * @property string $enforcedGroupIds      JSON array
 * @property string $exemptUserIds         JSON array
 * @property int    $failureLimit
 * @property int    $failureLockoutMinutes
 * @property string $protectedActions      JSON object
 */
class SettingsRecord extends ActiveRecord
{
    public static function tableName(): string
    {
        return '{{%mfaenforcer_settings}}';
    }
}
