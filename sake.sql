-- phpMyAdmin SQL Dump

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `sake`
--

-- --------------------------------------------------------

--
-- Table structure for table `sakeprotocol`
--

CREATE TABLE `sakeprotocol` (
  `id` int(11) NOT NULL,
  `d_enc_records` varchar(300) NOT NULL,
  `d_enc_iv` varchar(128) NOT NULL,
  `d_enc_tag` varchar(128) NOT NULL,
  `d_otid_old` text NOT NULL,
  `d_otid_new` text NOT NULL,
  `d_rev_status` int(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `sakeprotocol`
--

INSERT INTO `sakeprotocol` (`id`, `d_enc_records`, `d_enc_iv`, `d_enc_tag`, `d_otid_old`, `d_otid_new`, `d_rev_status`) VALUES
(14, '951207808b1ecb003d256f35cd97f079029a006cb6aec640f498a4f23392f56948876903428a9e0e5a77d90052989dac9a084af5eee387d694fce19ff0d1d9109b', 'cbc6b579811425152dbe9c5b', '494f6c404338660ffd09dae4617cdedf', '53b4ba46cebea1b1df7b12fb94be87e4', 'f1650c5e5a1b70de64589e0421f751c9', 0),
(15, '729c94c17ef22e2919debbc85364c351cb3164e2d178a436967cce18cb4dcdb3b5e9dfc9e8141b944c0056288b6479963d', '0af7c669294eb89c53788304', '5916f869014f51ed37e03c8395f9d174', '02d32f281e30b69ff1d47fe66602f5f1', 'd8c77cca230c6ffeca291342e95aa8eb', 0);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `sakeprotocol`
--
ALTER TABLE `sakeprotocol`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `sakeprotocol`
--
ALTER TABLE `sakeprotocol`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
