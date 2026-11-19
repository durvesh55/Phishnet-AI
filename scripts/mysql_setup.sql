-- Run ONCE as a MySQL admin:  mysql -u root -p < scripts/mysql_setup.sql
-- Replace the password below first. The app user gets rights ONLY on its own two databases.
CREATE DATABASE IF NOT EXISTS phishnet      CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE DATABASE IF NOT EXISTS phishnet_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS 'phishnet'@'localhost' IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
CREATE USER IF NOT EXISTS 'phishnet'@'%'         IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON phishnet.*      TO 'phishnet'@'localhost', 'phishnet'@'%';
GRANT ALL PRIVILEGES ON phishnet_test.* TO 'phishnet'@'localhost', 'phishnet'@'%';
FLUSH PRIVILEGES;
