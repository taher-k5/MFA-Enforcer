<?php

namespace modules\actionmfa\migrations;

use craft\db\Migration;

/**
 * Migration: move Action MFA settings from project config into the database.
 * Existing installations run this migration; fresh installs go through Install.php.
 */
class m260515_000001_add_settings_table extends Migration
{
    public function safeUp(): bool
    {
        if ($this->db->tableExists('{{%actionmfa_settings}}')) {
            return true;
        }

        $this->createTable('{{%actionmfa_settings}}', [
            'id'                    => $this->primaryKey(),
            'enforcedGroupIds'      => $this->text()->notNull(),
            'exemptUserIds'         => $this->text()->notNull(),
            'failureLimit'          => $this->integer()->notNull()->defaultValue(5),
            'failureLockoutMinutes' => $this->integer()->notNull()->defaultValue(5),
            'protectedActions'      => $this->mediumText()->notNull(),
            'dateCreated'           => $this->dateTime()->notNull(),
            'dateUpdated'           => $this->dateTime()->notNull(),
            'uid'                   => $this->uid(),
        ]);

        // Seed one empty-defaults row so a first load always has a record.
        $this->insert('{{%actionmfa_settings}}', [
            'enforcedGroupIds'      => '[]',
            'exemptUserIds'         => '[]',
            'failureLimit'          => 5,
            'failureLockoutMinutes' => 5,
            'protectedActions'      => '{}',
            'dateCreated'           => (new \DateTime())->format('Y-m-d H:i:s'),
            'dateUpdated'           => (new \DateTime())->format('Y-m-d H:i:s'),
            'uid'                   => \craft\helpers\StringHelper::UUID(),
        ]);

        return true;
    }

    public function safeDown(): bool
    {
        $this->dropTableIfExists('{{%actionmfa_settings}}');
        return true;
    }
}
