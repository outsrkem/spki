/*
 Target Server Type    : MySQL
 Target Server Version : 50744
 File Encoding         : 65001
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for certificate
-- ----------------------------
DROP TABLE IF EXISTS `certificate`;
CREATE TABLE `certificate`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `certid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `user_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `title` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '证书的友好名称',
  `subject` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '证书的Subject',
  `parent_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL COMMENT '上级证书ID，根CA为NULL',
  `pathlev` tinyint(4) NOT NULL COMMENT '证书层级，ca:0、中间证书：1、服务证书2',
  `genre` tinyint(4) NOT NULL COMMENT '证书类型，根ca:1,中间ca2，服务证书3',
  `cert_req` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '证书请求文件',
  `alarm` tinyint(1) NOT NULL DEFAULT 0 COMMENT '是否参与到期告警，0关闭 1开启',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_certid`(`certid`) USING BTREE,
  INDEX `idx_parent_id`(`parent_id`) USING BTREE,
  INDEX `idx_user_id`(`user_id`) USING BTREE,
  INDEX `idx_genre`(`genre`) USING BTREE,
  INDEX `idx_alarm`(`alarm`) USING BTREE,
  CONSTRAINT `certificate_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `creator` (`user_id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE = InnoDB AUTO_INCREMENT = 112 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Table structure for creator
-- ----------------------------
DROP TABLE IF EXISTS `creator`;
CREATE TABLE `creator`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `sync_time` bigint(20) NULL DEFAULT NULL COMMENT '毫秒时间戳',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_user_id`(`user_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Table structure for private_key
-- ----------------------------
DROP TABLE IF EXISTS `private_key`;
CREATE TABLE `private_key`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `keyid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `private_key` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `passphrase` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '加密后的口令',
  `fingerprint` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '公钥SHA256指纹',
  `create_time` bigint(20) NULL DEFAULT NULL COMMENT '毫秒时间戳',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_pubkey_fingerprint`(`fingerprint`) USING BTREE,
  UNIQUE INDEX `uk_keyid`(`keyid`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 95 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Table structure for version
-- ----------------------------
DROP TABLE IF EXISTS `version`;
CREATE TABLE `version`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `revision` int(11) NOT NULL COMMENT '版本号，从1递增',
  `certid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `keyid` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `serial` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '证书序列号',
  `fingerprint` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '证书SHA256指纹',
  `cert` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '证书文件主体',
  `effective_time` bigint(20) NULL DEFAULT NULL COMMENT '生效时间戳（毫秒）',
  `expiration_time` bigint(20) NULL DEFAULT NULL COMMENT '到期时间戳（毫秒）',
  `revocation_time` bigint(20) NULL DEFAULT NULL COMMENT '吊销时间戳（毫秒）',
  `state` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'V' COMMENT 'V有效 R吊销 E过期',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_cert_fingerprint`(`fingerprint`) USING BTREE,
  UNIQUE INDEX `uk_cert_revision`(`certid`, `revision`) USING BTREE,
  INDEX `idx_expiration`(`expiration_time`) USING BTREE,
  INDEX `idx_serial`(`serial`) USING BTREE,
  INDEX `idx_state`(`state`) USING BTREE,
  INDEX `idx_keyid`(`keyid`) USING BTREE,
  CONSTRAINT `fk_ver_key` FOREIGN KEY (`keyid`) REFERENCES `private_key` (`keyid`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `version_ibfk_1` FOREIGN KEY (`certid`) REFERENCES `certificate` (`certid`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE = InnoDB AUTO_INCREMENT = 115 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

SET FOREIGN_KEY_CHECKS = 1;
