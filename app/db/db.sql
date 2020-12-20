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
  PRIMARY KEY (`log_id`),
  UNIQUE KEY `token_UNIQUE` (`token`),
  CONSTRAINT `token` FOREIGN KEY (`token`) REFERENCES `nodes` (`token`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `general_logs`
--

LOCK TABLES `general_logs` WRITE;
/*!40000 ALTER TABLE `general_logs` DISABLE KEYS */;
INSERT INTO `general_logs` VALUES (1,'2020-01-01 10:10:10','cowrie','192.168.12.123','54234','192.168.12.124','80','TCP','1');
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
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nodes`
--

LOCK TABLES `nodes` WRITE;
/*!40000 ALTER TABLE `nodes` DISABLE KEYS */;
INSERT INTO `nodes` VALUES (1,'cowrie','192.168.1.200','255.255.255.0','ssh','null',1,'2020-01-01 10:10:10','False','1','2022-01-01 10:10:10'),(3,'dionea','192.168.1.1','255.255.255.0','test','null',123,'2020-01-01 10:10:10','True','2','2022-01-01 10:10:10');
/*!40000 ALTER TABLE `nodes` ENABLE KEYS */;
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

-- Dump completed on 2020-12-20 20:31:27
