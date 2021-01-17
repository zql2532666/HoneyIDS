-- MySQL dump 10.13  Distrib 8.0.22, for Linux (x86_64)
--
-- Host: localhost    Database: HoneyIDS
-- ------------------------------------------------------
-- Server version	8.0.22-0ubuntu0.20.04.3

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
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
) ENGINE=InnoDB AUTO_INCREMENT=130 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

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
) ENGINE=InnoDB AUTO_INCREMENT=170 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

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
) ENGINE=InnoDB AUTO_INCREMENT=40 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

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
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `virus_total_logs`
--

DROP TABLE IF EXISTS `virus_total_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `virus_total_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `scan_id` varchar(200) DEFAULT NULL,
  `md5` varchar(200) DEFAULT NULL,
  `sha1` varchar(200) DEFAULT NULL,
  `sha256` varchar(200) DEFAULT NULL,
  `scan_date` varchar(200) DEFAULT NULL,
  `permalink` varchar(200) DEFAULT NULL,
  `positives` int DEFAULT NULL,
  `total` int DEFAULT NULL,
  `scans` json DEFAULT NULL,
  `zipped_file_path` varchar(200) DEFAULT NULL,
  `time_at_file_received` varchar(200) DEFAULT NULL,
  `token` varchar(200) DEFAULT NULL,
  `response` int DEFAULT NULL,
  `zipped_file_password` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-01-17 15:56:40
