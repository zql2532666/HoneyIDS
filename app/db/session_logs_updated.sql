-- MySQL dump 10.13  Distrib 8.0.22, for Linux (x86_64)
--
-- Host: localhost    Database: HoneyIDS
-- ------------------------------------------------------
-- Server version	8.0.22-0ubuntu0.20.04.3

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
-- Table structure for table `session_logs`
--

DROP TABLE IF EXISTS `session_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `session_logs` (
  `session_log_id` int NOT NULL AUTO_INCREMENT,
  `honeynode_name` varchar(45) DEFAULT NULL,
  `source_ip` varchar(45) DEFAULT NULL,
  `source_port` varchar(45) DEFAULT NULL,
  `destination_ip` varchar(45) DEFAULT NULL,
  `destination_port` varchar(45) DEFAULT NULL,
  `commands` json DEFAULT NULL,
  `logged_in` json DEFAULT NULL,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `session` varchar(45) NOT NULL,
  `urls` json DEFAULT NULL,
  `credentials` json DEFAULT NULL,
  `hashes` json DEFAULT NULL,
  `version` varchar(100) DEFAULT NULL,
  `unknown_commands` json DEFAULT NULL,
  PRIMARY KEY (`session_log_id`,`session`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `session_logs`
--

LOCK TABLES `session_logs` WRITE;
/*!40000 ALTER TABLE `session_logs` DISABLE KEYS */;
INSERT INTO `session_logs` VALUES (2,'Cowrie-Test','192.168.148.146','36492','192.168.148.150','22','[\"ls\", \"whoami\", \"exit\"]','[\"root\", \"sunshine\"]','2021-01-14 08:35:04','2021-01-14 08:35:12','183a833033e3','[]','[]','[]','SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1','[]'),(3,'Cowrie-Test','192.168.148.146','36522','192.168.148.150','22','[\"ping www.google.com\", \"cat /etc/passwd\", \"exit\"]','[\"root\", \"sunshine\"]','2021-01-14 08:36:48','2021-01-14 08:37:10','fc89750167d6','[]','[]','[]','SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1','[]'),(4,'Cowrie-Test','192.168.148.146','36536','192.168.148.150','22','[\"test\", \"unknown\", \"cat /etc/os-release \", \"cd /etc\", \"ls\", \"cat dhcp\", \"cd dhcp\", \"ls\", \"cat dhclient.conf \", \"exit\"]','[\"root\", \"sunshine\"]','2021-01-14 08:37:26','2021-01-14 08:37:56','89768e1e0ff9','[]','[]','[]','SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1','[\"test\", \"unknown\"]');
/*!40000 ALTER TABLE `session_logs` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-01-14 16:39:12
