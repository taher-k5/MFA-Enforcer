<?php

namespace sfsinfotech\craftmfaenforcer\migrations;

use craft\db\Migration;

/**
 * Migration: add per-user TOTP secret storage table.
 * Existing installations run this migration; fresh installs go through Install.php.
 */
class m260526_000001_add_user_secrets_table extends Migration
{
    public function safeUp(): bool
    {
        if ($this->db->tableExists('{{%mfaenforcer_user_secrets}}')) {
            return true;
        }

        $this->createTable('{{%mfaenforcer_user_secrets}}', [
            'id'          => $this->primaryKey(),
            'userId'      => $this->integer()->notNull(),
            'secret'      => $this->string(255)->notNull(),
            'enabled'     => $this->boolean()->notNull()->defaultValue(false),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid'         => $this->uid(),
        ]);

        $this->createIndex(null, '{{%mfaenforcer_user_secrets}}', ['userId'], true);

        $this->addForeignKey(
            null,
            '{{%mfaenforcer_user_secrets}}',
            ['userId'],
            '{{%users}}',
            ['id'],
            'CASCADE',
            null
        );

        return true;
    }

    public function safeDown(): bool
    {
        $this->dropTableIfExists('{{%mfaenforcer_user_secrets}}');
        return true;
    }
}
