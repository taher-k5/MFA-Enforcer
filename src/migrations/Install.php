<?php

namespace modules\actionmfa\migrations;

use craft\db\Migration;

class Install extends Migration
{
    public string $driver;

    public function safeUp(): bool
    {
        $this->driver = \Craft::$app->getConfig()->getDb()->driver;

        if (!$this->db->tableExists('{{%actionmfa_tokens}}')) {
            $this->createTable('{{%actionmfa_tokens}}', [
                'id' => $this->primaryKey(),
                'userId' => $this->integer()->notNull(),
                'token' => $this->string(64)->notNull(),
                'actionKey' => $this->string(64)->notNull(),
                'expiresAt' => $this->dateTime()->notNull(),
                'usedAt' => $this->dateTime()->null(),
                'dateCreated' => $this->dateTime()->notNull(),
                'dateUpdated' => $this->dateTime()->notNull(),
                'uid' => $this->uid(),
            ]);

            $this->createIndex(null, '{{%actionmfa_tokens}}', ['token'], true);
            $this->createIndex(null, '{{%actionmfa_tokens}}', ['userId', 'actionKey']);

            $this->addForeignKey(
                null,
                '{{%actionmfa_tokens}}',
                ['userId'],
                '{{%users}}',
                ['id'],
                'CASCADE',
                null
            );
        }

        if (!$this->db->tableExists('{{%actionmfa_settings}}')) {
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
        }

        return true;
    }

    public function safeDown(): bool
    {
        $this->dropTableIfExists('{{%actionmfa_settings}}');
        $this->dropTableIfExists('{{%actionmfa_tokens}}');
        return true;
    }
}
