<?php

namespace sfsinfotech\craftmfaenforcer\models;

use craft\base\Model;

class Settings extends Model
{
    // Operations available per resource type for the scoped matrix.
    public const SCOPED_OPS = [
        'entry' => ['save', 'delete'],
        'globalSet' => ['save'],
        'category' => ['save', 'delete'],
    ];

    // ---- General settings ----
    public array $enforcedGroupIds = [];
    public array $exemptUserIds = [];
    public int $failureLimit = 5;
    public int $failureLockoutMinutes = 5;

    /**
     * Flat associative map of "type.id.op" => true for scoped resources.
     *
     * Examples:
     *   "entry.42.save"          — Entry section 42, save operation
     *   "globalSet.3.save"       — Global set id 3, save operation
     */
    public array $protectedActions = [];

    public function rules(): array
    {
        return [
            [['enforcedGroupIds', 'exemptUserIds', 'protectedActions'], 'each', 'rule' => ['safe']],
            [['failureLimit', 'failureLockoutMinutes'], 'integer', 'min' => 1],
        ];
    }

    public function isScopedActionProtected(string $type, ?int $resourceId, string $op): bool
    {
        if ($resourceId === null) {
            return false;
        }
        return !empty($this->protectedActions["{$type}.{$resourceId}.{$op}"]);
    }

    public function hasAnyScopedProtection(string $type): bool
    {
        $prefix = $type . '.';
        foreach ($this->protectedActions as $key => $on) {
            if ($on && str_starts_with((string)$key, $prefix) && substr_count($key, '.') === 2) {
                return true;
            }
        }
        return false;
    }

    public function isUserExempt(int $userId): bool
    {
        return in_array($userId, array_map('intval', $this->exemptUserIds), true);
    }

    public function userInEnforcedGroup(array $userGroupIds): bool
    {
        if (empty($this->enforcedGroupIds)) {
            return true;
        }
        return !empty(array_intersect(
            array_map('intval', $this->enforcedGroupIds),
            array_map('intval', $userGroupIds)
        ));
    }
}
