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
  `token` varchar(45) DEFAULT NULL,
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
INSERT INTO `session_logs` VALUES (1,'ba087387-6db1-4b22-8430-0629ad5c9e20','Cowrie-Test','192.168.148.146','38536','192.168.148.150','22','[\"hello\", \"whoami\", \"ls\", \"exit\"]','[\"root\", \"sunshine\"]','2021-01-14 12:12:40','2021-01-14 12:12:51','ad57005b1d00','[]','[]','[]','SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1','[\"hello\"]'),(2,'ba087387-6db1-4b22-8430-0629ad5c9e20','Cowrie-Test','192.168.148.146','38568','192.168.148.150','22','[\"ls\", \"exit\"]','[\"root\", \"sunshine\"]','2021-01-14 12:15:24','2021-01-14 12:15:31','52d60b69b6a4','[]','[]','[]','SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1','[]'),(3,'ba087387-6db1-4b22-8430-0629ad5c9e20','Cowrie-Test','192.168.148.146','38582','192.168.148.150','22','[\"whoami\", \"ls\", \"date\"]','[\"root\", \"sunshine\"]','2021-01-14 12:16:08','2021-01-14 12:19:11','7880f58b7b9f','[]','[]','[]','SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1','[]'),(4,'ba087387-6db1-4b22-8430-0629ad5c9e20','Cowrie-Test','192.168.148.146','38664','192.168.148.150','22','[\"date\", \"exit\"]','[\"root\", \"sunshine\"]','2021-01-14 20:24:51','2021-01-14 20:25:05','cacd276dd831','[]','[]','[]','SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1','[]');
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

-- Dump completed on 2021-01-14 20:32:30