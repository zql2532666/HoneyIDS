CREATE DATABASE  IF NOT EXISTS `HoneyIDS` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `HoneyIDS`;
-- MySQL dump 10.13  Distrib 8.0.22, for Linux (x86_64)
--
-- Host: localhost    Database: HoneyIDS
-- ------------------------------------------------------
-- Server version	8.0.22

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `general_logs`
--

DROP TABLE IF EXISTS `general_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `general_logs` (
  `log_id` int NOT NULL AUTO_INCREMENT,
  `capture_date` datetime DEFAULT NULL,
  `honeynode_name` varchar(45) DEFAULT NULL,
  `source_ip` varchar(45) DEFAULT NULL,
  `source_port` varchar(45) DEFAULT NULL,
  `destination_ip` varchar(45) DEFAULT NULL,
  `destination_port` varchar(45) DEFAULT NULL,
  `protocol` varchar(45) DEFAULT NULL,
  `token` varchar(45) NOT NULL,
  `raw_logs` json DEFAULT NULL,
  PRIMARY KEY (`log_id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `general_logs`
--

LOCK TABLES `general_logs` WRITE;
/*!40000 ALTER TABLE `general_logs` DISABLE KEYS */;
INSERT INTO `general_logs` VALUES (1,'2020-01-01 10:10:10','cowrie','192.168.12.123','54234','192.168.12.124','80','TCP','1','{\"urls\": [], \"hashes\": [], \"hostIP\": \"192.168.148.148\", \"peerIP\": \"192.168.148.146\", \"ttylog\": \"010000000000000000000000000000004e18b65f48d50b0003000000000000001e010........\", \"endTime\": \"2020-11-19T07:02:24.197533Z\", \"session\": \"df81514de4f2\", \"version\": \"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\", \"commands\": [\"ifconfig\", \"ls\", \"whoami\", \"cat /etc/passwd\", \"ls\", \"hello\", \"idk\", \"exit\"], \"hostPort\": 22, \"loggedin\": [\"root\", \"password\"], \"peerPort\": 43250, \"protocol\": \"ssh\", \"startTime\": \"2020-11-19T07:01:31.752063Z\", \"credentials\": [], \"unknownCommands\": [\"hello\", \"idk\"]}'),(10,'2020-01-01 10:10:10','Elastichoney','192.168.12.124','12341','192.168.12.124','80','TCP','1','{\"url\": \"192.168.148.149:9200/_search?pretty\", \"form\": \"pretty=&%7B%0A%09%09%09%22script_fields%22%3A+%7B%0A%09%09%09%09%22myscript%22%3A+%7B%0A%09%09%09%09%09%22script%22%3A+%22java.lang.Math.class.forName%28%5C%22java.lang.Runtime%5C%22%29.getRuntime%28%29.exec%28%5C%22whoami%5C%22%29.getText%28%29%22%0A%09%09%09%09%7D%0A%09%09%09%7D%0A%09%09%7D=\", \"type\": \"attack\", \"method\": \"POST\", \"source\": \"192.168.148.146\", \"headers\": {\"host\": \"192.168.148.149:9200\", \"user_agent\": \"curl/7.68.0\", \"content_type\": \"application/x-www-form-urlencoded\", \"accept_language\": \"\"}, \"payload\": \"\", \"honeypot\": \"218.212.205.87\", \"@timestamp\": \"2020-11-20T23:16:09.481527978+08:00\", \"payloadMd5\": \"\", \"payloadBinary\": \"\", \"payloadCommand\": \"\", \"payloadResource\": \"\"}'),(11,'2020-01-01 10:10:10','Wordpot','192.168.12.125','42343','192.168.12.124','80','TCP','1','{\"url\": \"http://localhost/wp-login.php\", \"plugin\": \"badlogin\", \"dest_ip\": \"0.0.0.0\", \"password\": \"admin\", \"username\": \"admin\", \"dest_port\": \"80\", \"source_ip\": \"127.0.0.1\", \"user_agent\": \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:79.0) Gecko/20100101 Firefox/79.0\", \"source_port\": 41622}'),(12,'2020-01-01 10:10:10','Drupot','192.168.12.126','12351','192.168.12.124','80','TCP','1','{\"app\": \"agave\", \"sensor\": \"8016308d-2a4c-11eb-8395-000c29aace21\", \"src_ip\": \"127.0.0.1\", \"channel\": \"agave.events\", \"dest_ip\": \"218.212.205.87\", \"protocol\": \"HTTP/1.1\", \"src_port\": 38478, \"agave_app\": \"Drupot\", \"dest_port\": 80, \"prev_seen\": false, \"signature\": \"\", \"request_json\": {\"URL\": {\"Host\": \"\", \"Path\": \"/search/node\", \"User\": null, \"Opaque\": \"\", \"Scheme\": \"\", \"RawPath\": \"\", \"Fragment\": \"\", \"RawQuery\": \"keys=test\", \"ForceQuery\": false, \"RawFragment\": \"\"}, \"Body\": \"\", \"Host\": \"localhost\", \"Proto\": \"HTTP/1.1\", \"Header\": {\"Accept\": [\"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\"], \"Referer\": [\"http://localhost/\"], \"Connection\": [\"keep-alive\"], \"User-Agent\": [\"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0\"], \"Accept-Encoding\": [\"gzip, deflate\"], \"Accept-Language\": [\"en-US,en;q=0.5\"], \"Upgrade-Insecure-Requests\": [\"1\"]}, \"Method\": \"GET\", \"PostForm\": {}, \"ProtoMajor\": 1, \"ProtoMinor\": 1, \"TransferEncoding\": null}, \"agave_client_version\": \"v0.1.2\"}'),(13,'2020-01-01 10:10:10','Shockpot','192.168.12.127','12367','192.168.12.124','80','TCP','1','{\"url\": \"http://localhost/cgi-bin/vulnerable\", \"path\": \"/cgi-bin/vulnerable\", \"method\": \"GET\", \"command\": \"None\", \"headers\": [[\"Accept\", \"*/*\"], [\"Host\", \"localhost\"], [\"User-Agent\"], [\"Content-Type\", \"text/plain\"], [\"Content-Length\", \"\"]], \"dest_host\": \"115.66.174.103\", \"dest_port\": \"80\", \"source_ip\": \"127.0.0.1\", \"timestamp\": \"2020-11-20 23:35:28.594395\", \"command_data\": \"None\", \"query_string\": \"\", \"is_shellshock\": \"True\"}'),(14,'2020-01-01 10:10:10','Sticky Elephant','192.168.12.128','63241','192.168.12.124','80','TCP','1','{\"raw\": \"[81,0,0,1,77,83,69,76,69,67,84,32,100,46,100,97,116,110,97,109,101,32,97,115,32,34,78,97,109,101,34,44,10,32,32,32,32,32,32,32,112,103,95,99,97,116,97,108,111,103,46,112,103,95,103,101,116,95,117,115,101,114,98,121,105,100,40,100,46,100,97,116,100,98,97,41,32,97,115,32,34,79,119,110,101,114,34,44,10,32,32,32,32,32,32,32,112,103,95,99,97,116,97,108,111,103,46,112,103,95,101,110,99,111,100,105,110,103,95,116,111,95,99,104,97,114,40,100,46,101,110,99,111,100,105,110,103,41,32,97,115,32,34,69,110,99,111,100,105,110,103,34,44,10,32,32,32,32,32,32,32,100,46,100,97,116,99,111,108,108,97,116,101,32,97,115,32,34,67,111,108,108,97,116,101,34,44,10,32,32,32,32,32,32,32,100,46,100,97,116,99,116,121,112,101,32,97,115,32,34,67,116,121,112,101,34,44,10,32,32,32,32,32,32,32,112,103,95,99,97,116,97,108,111,103,46,97,114,114,97,121,95,116,111,95,115,116,114,105,110,103,40,100,46,100,97,116,97,99,108,44,32,69,39,92,110,39,41,32,65,83,32,34,65,99,99,101,115,115,32,112,114,105,118,105,108,101,103,101,115,34,10,70,82,79,77,32,112,103,95,99,97,116,97,108,111,103,46,112,103,95,100,97,116,97,98,97,115,101,32,100,10,79,82,68,69,82,32,66,89,32,49,59,0]\", \"query\": \"QUERY:\", \"dest_ip\": \"192.168.148.149\", \"dest_port\": \"5432\", \"source_ip\": \"192.168.148.146\", \"source_port\": \"55714\"}');
/*!40000 ALTER TABLE `general_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nids_logs`
--

DROP TABLE IF EXISTS `nids_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `nids_logs` (
  `nids_log_id` int NOT NULL AUTO_INCREMENT,
  `date` datetime DEFAULT NULL,
  `honeynode_name` varchar(45) DEFAULT NULL,
  `source_ip` varchar(45) DEFAULT NULL,
  `source_port` varchar(45) DEFAULT NULL,
  `destination_ip` varchar(45) DEFAULT NULL,
  `destination_port` varchar(45) DEFAULT NULL,
  `priority` int DEFAULT NULL,
  `classification` int DEFAULT NULL,
  `signature` varchar(1000) DEFAULT NULL,
  PRIMARY KEY (`nids_log_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nids_logs`
--

LOCK TABLES `nids_logs` WRITE;
/*!40000 ALTER TABLE `nids_logs` DISABLE KEYS */;
INSERT INTO `nids_logs` VALUES (1,'2020-01-01 10:10:10','cowrie','192.168.1.1','123','192.168.2.2','22',2,3,'ET SCAN Suspicious inbound to mySQL port 3306');
/*!40000 ALTER TABLE `nids_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nodes`
--

DROP TABLE IF EXISTS `nodes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `nodes` (
  `node_id` int NOT NULL AUTO_INCREMENT,
  `honeynode_name` varchar(45) NOT NULL,
  `ip_addr` varchar(45) NOT NULL,
  `subnet_mask` varchar(45) NOT NULL,
  `honeypot_type` varchar(45) DEFAULT NULL,
  `nids_type` varchar(45) DEFAULT NULL,
  `no_of_attacks` int DEFAULT NULL,
  `date_deployed` datetime NOT NULL,
  `heartbeat_status` varchar(45) NOT NULL,
  `token` varchar(45) NOT NULL,
  `last_heard` datetime DEFAULT NULL,
  PRIMARY KEY (`node_id`),
  UNIQUE KEY `token_UNIQUE` (`token`),
  UNIQUE KEY `ip_addr_UNIQUE` (`ip_addr`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nodes`
--

LOCK TABLES `nodes` WRITE;
/*!40000 ALTER TABLE `nodes` DISABLE KEYS */;
INSERT INTO `nodes` VALUES (10,'test','192.168.1.1','255.255.255.0','nids','null',123,'2020-01-01 10:10:10','True','1','2010-05-09 07:41:54');
/*!40000 ALTER TABLE `nodes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `session_logs`
--

DROP TABLE IF EXISTS `session_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `session_logs` (
  `session_log_id` int NOT NULL AUTO_INCREMENT,
  `source_ip` varchar(45) DEFAULT NULL,
  `source_port` varchar(45) DEFAULT NULL,
  `destination_ip` varchar(45) DEFAULT NULL,
  `destination_port` varchar(45) DEFAULT NULL,
  `commands` text,
  `logged_in` text,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `session` varchar(45) NOT NULL,
  `urls` text,
  `credentials` text,
  `hashes` text,
  `version` varchar(100) DEFAULT NULL,
  `unknown_commands` text,
  PRIMARY KEY (`session_log_id`,`session`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `session_logs`
--

LOCK TABLES `session_logs` WRITE;
/*!40000 ALTER TABLE `session_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `session_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping events for database 'HoneyIDS'
--

--
-- Dumping routines for database 'HoneyIDS'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-12-30  0:51:17
