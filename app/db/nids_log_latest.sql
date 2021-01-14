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
-- Table structure for table `nids_logs`
--

DROP TABLE IF EXISTS `nids_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `nids_logs` (
  `nids_log_id` int NOT NULL AUTO_INCREMENT,
  `nids_type` varchar(45) DEFAULT NULL,
  `date` datetime DEFAULT NULL,
  `token` varchar(45) DEFAULT NULL,
  `honeynode_name` varchar(45) DEFAULT NULL,
  `source_ip` varchar(45) DEFAULT NULL,
  `source_port` varchar(45) DEFAULT NULL,
  `destination_ip` varchar(45) DEFAULT NULL,
  `destination_port` varchar(45) DEFAULT NULL,
  `priority` int DEFAULT NULL,
  `classification` int DEFAULT NULL,
  `signature` varchar(1000) DEFAULT NULL,
  `raw_logs` json DEFAULT NULL,
  PRIMARY KEY (`nids_log_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nids_logs`
--

LOCK TABLES `nids_logs` WRITE;
/*!40000 ALTER TABLE `nids_logs` DISABLE KEYS */;
INSERT INTO `nids_logs` VALUES (1,'snort','2021-01-14 16:34:32','ba087387-6db1-4b22-8430-0629ad5c9e20','Cowrie-Test','192.168.148.146','51290','192.168.148.150','3306',2,3,'ET SCAN Suspicious inbound to mySQL port 3306','{\"id\": 29406, \"tos\": 0, \"ttl\": 53, \"iplen\": 45056, \"proto\": \"TCP\", \"dgmlen\": 44, \"ethdst\": \"00:0C:29:AA:CE:21\", \"ethlen\": \"0x3C\", \"ethsrc\": \"00:0C:29:1C:81:D5\", \"header\": \"1:2010937:3\", \"sensor\": \"ba087387-6db1-4b22-8430-0629ad5c9e20\", \"tcpack\": \"0x0\", \"tcplen\": 24, \"tcpseq\": \"0xEDD12B13\", \"tcpwin\": \"0x4000000\", \"ethtype\": \"0x800\", \"priority\": 2, \"tcpflags\": \"******S*\", \"signature\": \"ET SCAN Suspicious inbound to mySQL port 3306\", \"source_ip\": \"192.168.148.146\", \"timestamp\": \"2021/01/14 16:34:31.702505\", \"source_port\": 51290, \"classification\": 3, \"destination_ip\": \"192.168.148.150\", \"destination_port\": 3306}'),(2,'snort','2021-01-14 16:36:31','ba087387-6db1-4b22-8430-0629ad5c9e20','Cowrie-Test','192.168.148.146','64597','192.168.148.150','3306',2,3,'ET SCAN Suspicious inbound to mySQL port 3306','{\"id\": 37804, \"tos\": 0, \"ttl\": 39, \"iplen\": 45056, \"proto\": \"TCP\", \"dgmlen\": 44, \"ethdst\": \"00:0C:29:AA:CE:21\", \"ethlen\": \"0x3C\", \"ethsrc\": \"00:0C:29:1C:81:D5\", \"header\": \"1:2010937:3\", \"sensor\": \"ba087387-6db1-4b22-8430-0629ad5c9e20\", \"tcpack\": \"0x0\", \"tcplen\": 24, \"tcpseq\": \"0xF213B425\", \"tcpwin\": \"0x4000000\", \"ethtype\": \"0x800\", \"priority\": 2, \"tcpflags\": \"******S*\", \"signature\": \"ET SCAN Suspicious inbound to mySQL port 3306\", \"source_ip\": \"192.168.148.146\", \"timestamp\": \"2021/01/14 16:36:31.197618\", \"source_port\": 64597, \"classification\": 3, \"destination_ip\": \"192.168.148.150\", \"destination_port\": 3306}');
/*!40000 ALTER TABLE `nids_logs` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-01-14 16:38:58
