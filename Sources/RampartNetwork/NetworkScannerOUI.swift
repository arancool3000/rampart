import Foundation

/// Small bundled OUI (MAC prefix → vendor) table for the vendors most common on home networks, plus a
/// device-type guesser. Not exhaustive on purpose: an unknown prefix just means "unknown vendor".
public enum OUITable {
    /// Lowercase `aa:bb:cc` prefixes grouped by vendor. First match wins when a prefix is listed twice.
    static let vendors: [(String, [String])] = [
        ("Apple", ["00:03:93", "00:0a:95", "00:0d:93", "00:16:cb", "00:17:f2", "00:19:e3", "00:1b:63", "00:1c:b3", "00:1d:4f", "00:1e:52",
                   "00:1e:c2", "00:1f:5b", "00:1f:f3", "00:21:e9", "00:23:12", "00:23:df", "00:25:00", "00:25:bc", "00:26:08", "00:26:bb",
                   "00:88:65", "14:7d:da", "18:af:61", "20:c9:d0", "24:a0:74", "28:cf:e9", "2c:be:08", "34:c0:59", "38:c9:86", "3c:07:54",
                   "3c:15:c2", "40:6c:8f", "48:d7:05", "54:26:96", "5c:95:ae", "5c:f9:38", "60:33:4b", "64:b9:e8", "68:a8:6d", "6c:40:08",
                   "70:56:81", "78:31:c1", "78:7b:8a", "7c:6d:62", "80:e6:50", "84:38:35", "8c:58:77", "8c:85:90", "90:72:40", "98:fe:94",
                   "a0:99:9b", "a4:5e:60", "a4:83:e7", "a8:86:dd", "ac:87:a3", "ac:bc:32", "b0:34:95", "b8:09:8a", "b8:e8:56", "bc:52:b7",
                   "c0:84:7a", "c4:2c:03", "c8:2a:14", "d0:03:4b", "d0:23:db", "d4:9a:20", "d8:a2:5e", "dc:a9:04", "e0:f8:47", "e4:ce:8f",
                   "f0:18:98", "f0:b4:79", "f0:d1:a9", "f4:0f:24", "f4:f1:5a", "f8:1e:df", "a4:b1:97", "bc:d0:74", "f0:99:bf", "3c:22:fb",
                   "88:66:a5", "a8:5c:2c", "dc:2b:2a", "e0:b9:ba", "10:40:f3", "34:36:3b", "48:bf:6b", "70:cd:60", "9c:f3:87", "d0:81:7a"]),
        ("Google", ["3c:5a:b4", "54:60:09", "94:eb:2c", "a4:77:33", "f4:f5:d8", "f8:8f:ca", "1c:f2:9a", "48:d6:d5", "6c:ad:f8", "20:df:b9",
                    "30:fd:38", "d8:6c:63", "e4:f0:42", "00:1a:11", "44:07:0b", "70:3a:cb", "7c:d9:5c", "98:d2:93", "64:16:66", "18:b4:30",
                    "58:cb:52", "08:9e:08", "cc:f4:11", "1c:53:f9", "28:bd:89", "e8:d8:d1"]),
        ("Amazon", ["00:fc:8b", "0c:47:c9", "10:ae:60", "18:74:2e", "34:d2:70", "40:b4:cd", "44:65:0d", "50:dc:e7", "68:37:e9", "6c:56:97",
                    "74:c2:46", "78:e1:03", "84:d6:d0", "8c:ea:48", "a0:02:dc", "ac:63:be", "b4:7c:9c", "f0:27:2d", "f0:f0:a4", "fc:65:de",
                    "fc:a1:83", "38:f7:3d", "1c:12:b0", "0c:ee:99", "48:b4:23", "cc:f7:35", "f0:81:73", "44:3d:54", "1c:fe:2b", "08:7c:39"]),
        ("Ring", ["34:3e:a4", "54:e0:19", "9c:76:13"]),
        ("Samsung", ["00:12:47", "00:15:99", "00:16:32", "00:17:c9", "00:1a:8a", "00:1d:25", "00:21:19", "00:23:39", "00:24:54", "00:26:37",
                     "08:d4:2b", "10:1d:c0", "18:3a:2d", "1c:66:aa", "24:4b:03", "28:ba:b5", "30:cd:a7", "34:23:ba", "38:aa:3c", "3c:5a:37",
                     "40:0e:85", "50:01:bb", "5c:0a:5b", "60:6b:bd", "78:47:1d", "8c:71:f8", "8c:77:12", "94:35:0a", "9c:3a:af", "a0:21:95",
                     "b4:62:93", "bc:72:b1", "c4:73:1e", "cc:07:ab", "d0:17:c2", "d8:57:ef", "e8:50:8b", "ec:1f:72", "f4:7b:5e", "fc:a1:3e",
                     "8c:f5:a3", "84:25:db", "50:cc:f8", "14:49:e0", "34:be:00", "38:2d:d1", "70:f9:27", "ac:5f:3e", "cc:6e:a4", "e4:7c:f9"]),
        ("TP-Link", ["00:27:19", "14:cc:20", "14:cf:92", "18:a6:f7", "1c:3b:f3", "30:b5:c2", "50:c7:bf", "54:af:97", "5c:62:8b", "60:32:b1",
                     "60:e3:27", "64:70:02", "70:4f:57", "74:da:88", "84:16:f9", "90:f6:52", "98:da:c4", "a4:2b:b0", "ac:84:c6", "b0:4e:26",
                     "b0:48:7a", "b0:95:75", "c0:06:c3", "c4:6e:1f", "c4:e9:84", "cc:32:e5", "d8:07:b6", "e8:de:27", "ec:08:6b", "ec:17:2f",
                     "f4:ec:38", "f4:f2:6d", "00:31:92", "28:ee:52", "3c:84:6a", "48:22:54", "6c:5a:b0", "9c:a2:f4", "10:27:f5", "1c:61:b4",
                     "24:2f:d0", "30:de:4b", "34:60:f9", "40:ae:30", "5c:a6:e6", "7c:c2:c6", "98:25:4a", "a8:42:a1", "b4:b0:24", "e4:fa:c4",
                     "e8:48:b8", "60:a4:b7", "68:ff:7b", "d4:6e:0e", "e4:c3:2a"]),
        ("Netgear", ["00:09:5b", "00:0f:b5", "00:14:6c", "00:1b:2f", "00:1e:2a", "00:1f:33", "00:22:3f", "00:24:b2", "00:26:f2", "04:a1:51",
                     "08:02:8e", "08:bd:43", "10:0c:6b", "10:da:43", "20:4e:7f", "20:e5:2a", "28:c6:8e", "2c:30:33", "30:46:9a", "3c:37:86",
                     "44:94:fc", "6c:b0:ce", "74:44:01", "84:1b:5e", "9c:3d:cf", "a0:04:60", "a0:21:b7", "a0:63:91", "b0:39:56", "b0:7f:b9",
                     "b0:b9:8a", "c0:3f:0e", "c0:ff:d4", "c4:04:15", "c4:3d:c7", "cc:40:d0", "dc:ef:09", "e0:46:9a", "e4:f4:c6", "e8:fc:af",
                     "9c:c9:eb", "6c:cd:d6", "94:a6:7e", "8c:3b:ad", "38:94:ed", "10:0c:6b"]),
        ("Ubiquiti", ["00:15:6d", "00:27:22", "04:18:d6", "18:e8:29", "24:5a:4c", "24:a4:3c", "44:d9:e7", "60:22:32", "68:72:51", "70:a7:41",
                      "74:83:c2", "74:ac:b9", "78:45:58", "78:8a:20", "80:2a:a8", "9c:05:d6", "b4:fb:e4", "d0:21:f9", "d8:b3:70", "dc:9f:db",
                      "e0:63:da", "f0:9f:c2", "f4:92:bf", "fc:ec:da", "28:70:4e", "94:2a:6f", "ac:8b:a9", "e4:38:83", "f4:e2:c6", "1e:f4:1e"]),
        ("ASUS", ["00:0c:6e", "00:0e:a6", "00:11:2f", "00:11:d8", "00:13:d4", "00:15:f2", "00:17:31", "00:18:f3", "00:1a:92", "00:1b:fc",
                  "00:1d:60", "00:1e:8c", "00:1f:c6", "00:22:15", "00:23:54", "00:24:8c", "00:26:18", "04:92:26", "04:d4:c4", "04:d9:f5",
                  "08:60:6e", "08:62:66", "0c:9d:92", "10:7b:44", "10:bf:48", "10:c3:7b", "14:dd:a9", "1c:87:2c", "1c:b7:2c", "20:cf:30",
                  "2c:4d:54", "2c:56:dc", "2c:fd:a1", "30:5a:3a", "30:85:a9", "34:97:f6", "38:2c:4a", "38:d5:47", "3c:7c:3f", "40:16:7e",
                  "40:b0:76", "48:5b:39", "4c:ed:fb", "50:46:5d", "50:eb:f6", "54:04:a6", "54:a0:50", "58:11:22", "60:45:cb", "60:a4:4c",
                  "70:4d:7b", "70:8b:cd", "74:d0:2b", "78:24:af", "88:d7:f6", "90:e6:ba", "9c:5c:8e", "a0:36:bc", "a8:5e:45", "ac:22:0b",
                  "ac:9e:17", "b0:6e:bf", "bc:ae:c5", "bc:ee:7b", "c8:60:00", "d4:5d:64", "d8:50:e6", "e0:3f:49", "e0:cb:4e", "f0:2f:74",
                  "f0:79:59", "f4:6d:04", "fc:34:97", "24:4b:fe", "7c:10:c9"]),
        ("Raspberry Pi", ["b8:27:eb", "dc:a6:32", "e4:5f:01", "28:cd:c1", "d8:3a:dd", "2c:cf:67"]),
        ("Espressif", ["24:0a:c4", "24:6f:28", "24:62:ab", "30:ae:a4", "3c:71:bf", "40:f5:20", "48:3f:da", "4c:11:ae", "4c:75:25", "54:5a:a6",
                       "5c:cf:7f", "60:01:94", "68:c6:3a", "70:03:9f", "7c:9e:bd", "80:7d:3a", "84:0d:8e", "84:cc:a8", "84:f3:eb", "8c:aa:b5",
                       "90:97:d5", "94:b9:7e", "98:f4:ab", "a0:20:a6", "a4:7b:9d", "a4:cf:12", "ac:67:b2", "b4:e6:2d", "bc:dd:c2", "c4:4f:33",
                       "c8:2b:96", "cc:50:e3", "d8:a0:1d", "d8:bf:c0", "dc:4f:22", "e8:db:84", "ec:fa:bc", "f4:cf:a2", "fc:f5:c4", "10:52:1c",
                       "34:ab:95", "08:3a:f2", "08:b6:1f", "0c:b8:15", "34:85:18", "40:22:d8", "48:e7:29", "58:bf:25", "7c:df:a1", "94:3c:c6",
                       "a0:a3:b3", "c0:49:ef", "e0:5a:1b", "24:dc:c3", "30:c6:f7", "3c:61:05", "44:17:93", "4c:eb:d6", "78:21:84", "8c:4b:14",
                       "a8:03:2a", "b0:a7:32", "c8:c9:a3", "d4:8a:fc", "e8:68:e7", "ec:62:60", "f0:08:d1", "fc:b4:67", "2c:f4:32", "50:02:91",
                       "60:55:f9", "84:fc:e6", "24:b2:de", "18:fe:34", "3c:84:27", "64:b7:08", "70:04:1d", "78:ee:4c", "8c:ce:4e", "94:e6:86",
                       "b4:8a:0a", "48:27:e2", "24:ec:4a", "34:94:54", "48:55:19", "4c:ca:5f", "54:32:04", "58:cf:79", "70:b8:f6", "9c:9c:1f",
                       "a0:b7:65", "b8:d6:1a", "c4:5b:be", "c4:de:e2", "e8:31:cd", "f4:12:fa"]),
        ("Sonos", ["00:0e:58", "34:7e:5c", "48:a6:b8", "5c:aa:fd", "78:28:ca", "94:9f:3e", "b8:e9:37", "c4:38:75", "54:2a:1b"]),
        ("Roku", ["00:0d:4b", "08:05:81", "10:59:32", "20:ef:bd", "84:ea:ed", "88:de:a9", "8c:49:62", "ac:3a:7a", "b0:a7:37", "b8:3e:59",
                  "b8:a1:75", "c8:3a:6b", "cc:6d:a0", "d0:4d:2c", "d4:e2:2f", "d8:31:34", "dc:3a:5e", "e0:b5:2d"]),
        ("HP", ["00:01:e6", "00:01:e7", "00:02:a5", "00:04:ea", "00:08:02", "00:0a:57", "00:0b:cd", "00:0d:9d", "00:0e:7f", "00:0f:20",
                "00:0f:61", "00:10:83", "00:10:e3", "00:11:0a", "00:11:85", "00:12:79", "00:13:21", "00:14:38", "00:14:c2", "00:15:60",
                "00:16:35", "00:17:08", "00:17:a4", "00:18:fe", "00:19:bb", "00:1a:4b", "00:1b:78", "00:1c:c4", "00:1e:0b", "00:1f:29",
                "00:21:5a", "00:22:64", "00:23:7d", "00:24:81", "00:25:b3", "00:26:55", "00:30:6e", "00:30:c1", "00:50:8b", "00:60:b0",
                "00:80:a0", "08:00:09", "10:1f:74", "10:60:4b", "14:02:ec", "18:a9:05", "1c:c1:de", "24:be:05", "28:80:23", "28:92:4a",
                "2c:27:d7", "2c:41:38", "2c:44:fd", "2c:59:e5", "2c:76:8a", "30:8d:99", "30:e1:71", "34:64:a9", "38:63:bb", "3c:4a:92",
                "3c:52:82", "3c:a8:2a", "3c:d9:2b", "40:a8:f0", "40:b0:34", "44:1e:a1", "44:31:92", "48:0f:cf", "4c:39:09", "5c:b9:01",
                "5c:8a:38", "6c:3b:e5", "6c:c2:17", "70:5a:0f", "78:48:59", "78:ac:c0", "78:e3:b5", "78:e7:d1", "80:c1:6e", "80:ce:62",
                "84:34:97", "88:51:fb", "8c:dc:d4", "94:57:a5", "98:4b:e1", "98:e7:f4", "9c:8e:99", "9c:b6:54", "a0:1d:48", "a0:2b:b8",
                "a0:48:1c", "a0:8c:fd", "a0:b3:cc", "a0:d3:c1", "a4:5d:36", "ac:16:2d", "b0:5a:da", "b4:39:d6", "b4:99:ba", "b4:b5:2f",
                "b4:b6:86", "c4:34:6b", "c4:65:16", "c8:cb:b8", "c8:d3:ff", "cc:3e:5f", "d0:7e:28", "d0:bf:9c", "d4:85:64", "d4:c9:ef",
                "d8:94:03", "d8:9d:67", "dc:4a:3e", "e4:11:5b", "e4:e7:49", "e8:39:35", "e8:f7:24", "ec:8e:b5", "ec:9a:74", "ec:b1:d7",
                "f0:62:81", "f0:92:1c", "f4:03:43", "f4:30:b9", "f4:ce:46", "fc:15:b4", "fc:3f:db"]),
        ("Brother", ["00:1b:a9", "00:80:77", "30:05:5c", "3c:2a:f4", "40:ac:8d", "94:dd:f8", "a4:ae:11", "b4:22:00", "24:95:2f", "2c:d2:6b", "04:5e:a4"]),
        ("Canon", ["00:1e:8f", "00:bb:c1", "18:0c:ac", "2c:9e:fc", "34:95:db", "60:12:8b", "74:bf:b7", "88:87:17", "f4:a9:97", "f8:0d:f0"]),
        ("Epson", ["00:00:48", "00:26:ab", "08:00:48", "38:9d:92", "44:d2:44", "64:eb:8c", "9c:ae:d3", "a4:ee:57", "ac:18:26", "e4:e7:49"]),
        ("Hikvision", ["18:68:cb", "28:57:be", "44:19:b6", "4c:bd:8f", "54:c4:15", "58:03:fb", "58:50:ed", "80:7c:62", "98:df:82", "a4:14:37",
                       "b4:a3:82", "bc:ad:28", "bc:ba:c2", "c0:51:7e", "c0:56:e3", "e0:ba:ad", "e0:ca:3c", "24:28:fd", "2c:a5:9c", "64:f2:fb",
                       "78:9e:84", "80:be:af", "98:8b:0a", "a0:ff:0c", "04:fe:8d", "48:ea:63", "bc:5e:33"]),
        ("Dahua", ["3c:ef:8c", "4c:11:bf", "8c:e7:48", "90:02:a9", "a0:bd:1d", "b4:4c:3b", "bc:32:5f", "e0:50:8b", "e4:24:6c", "14:a7:8b",
                   "24:52:6a", "38:af:29", "44:ad:19", "9c:14:63", "c8:b5:b7", "f4:b1:c2", "ec:71:db", "fc:5f:49", "50:ac:f4"]),
        ("Xiaomi", ["00:9e:c8", "04:cf:8c", "0c:1d:af", "10:2a:b3", "14:f6:5a", "18:59:36", "20:34:fb", "28:6c:07", "28:e3:1f", "34:80:b3",
                    "34:ce:00", "38:a4:ed", "3c:bd:3e", "40:31:3c", "4c:49:e3", "50:64:2b", "50:8f:4c", "58:44:98", "5c:e5:0c", "64:09:80",
                    "64:b4:73", "64:cc:2e", "68:df:dd", "74:23:44", "74:51:ba", "78:02:f8", "78:11:dc", "7c:1d:d9", "7c:49:eb", "8c:be:be",
                    "98:fa:e3", "9c:99:a0", "a4:50:46", "ac:c1:ee", "ac:f7:f3", "b0:e2:35", "c4:0b:cb", "c4:6a:b7", "d4:97:0b", "e8:ab:fa",
                    "ec:d0:9f", "f0:b4:29", "f4:8b:32", "f8:a4:5f", "fc:64:ba", "04:b4:fe", "24:4c:ab", "30:66:d0", "48:2c:a0", "50:ec:50",
                    "54:48:e6", "58:b6:23", "5c:02:14", "60:ab:67", "6c:c9:f8", "70:bb:e9", "74:ac:5f", "88:c3:97", "90:dd:5d", "94:ca:0f",
                    "a8:e3:ee", "b4:c9:b9", "c8:bf:4c", "d0:9f:d9", "e4:46:da", "e8:d5:1d"]),
        ("Philips Hue", ["00:17:88", "ec:b5:fa"]),
        ("Microsoft", ["28:18:78", "7c:1e:52", "98:5f:d3", "00:15:5d", "00:50:f2", "58:82:a8", "60:45:bd", "b4:ae:2b", "bc:83:85", "c8:3f:26",
                       "00:12:5a", "00:17:fa", "00:1d:d8", "00:22:48", "00:25:ae", "0c:41:3e", "30:59:b7", "48:50:73", "50:1a:c5", "6c:5d:3a",
                       "7c:ed:8d", "84:63:d6", "94:9a:a9", "a0:4a:5e", "c4:9d:ed", "dc:98:40", "ec:59:e7", "f0:1d:bc"]),
        ("Intel", ["3c:a9:f4", "a4:34:d9", "8c:8d:28", "48:51:c5", "00:1f:3c", "34:02:86", "00:21:6a", "00:24:d7", "00:27:10", "08:11:96",
                   "0c:8b:fd", "10:02:b5", "18:1d:ea", "28:16:ad", "34:13:e8", "3c:58:c2", "5c:51:4f", "60:57:18", "7c:7a:91", "80:86:f2",
                   "84:3a:4b", "8c:a9:82", "98:af:65", "a0:88:b4", "ac:d1:b8", "b4:6b:fc", "c8:94:02", "dc:71:96", "e4:02:9b", "f8:63:3f"]),
        ("Dell", ["00:14:22", "18:03:73", "18:a9:9b", "24:b6:fd", "34:17:eb", "5c:f9:dd", "84:2b:2b", "b0:83:fe", "d4:be:d9", "f0:1f:af",
                  "f8:b1:56", "f8:bc:12", "18:db:f2", "54:bf:64", "8c:ec:4b", "c8:f7:50", "98:e7:43", "00:1a:a0", "00:1e:4f", "00:21:9b",
                  "00:24:e8", "00:26:b9", "14:18:77", "14:fe:b5", "28:f1:0e", "4c:76:25", "74:86:7a", "a4:1f:72", "b8:ca:3a", "e4:54:e8"]),
        ("Lenovo", ["00:06:1b", "28:d2:44", "54:e1:ad", "60:d9:a0", "80:fa:5b", "98:fa:9b", "a4:8c:db", "c8:5b:76", "e8:6a:64", "f4:8c:50"]),
        ("Nintendo", ["00:17:ab", "00:19:1d", "00:1a:e9", "00:1b:7a", "00:1c:be", "00:1e:35", "00:1f:32", "00:21:47", "00:22:4c", "00:23:31",
                      "00:24:1e", "00:25:a0", "00:26:59", "04:03:d6", "18:2a:7b", "2c:10:c1", "34:af:2c", "40:d2:8a", "48:a5:e7", "58:bd:a3",
                      "5c:52:1e", "60:6b:ff", "64:b5:c6", "78:a2:a0", "7c:bb:8a", "8c:56:c5", "98:41:5c", "98:b6:e9", "9c:e6:35", "a4:5c:27",
                      "a4:c0:e1", "b8:78:26", "b8:ae:6e", "cc:9e:00", "cc:fb:65", "d8:6b:f7", "dc:68:eb", "e0:0c:7f", "e0:e7:51", "e8:4e:ce", "ec:c4:0d"]),
        ("Sony", ["00:04:1f", "00:13:a9", "00:15:c1", "00:19:c5", "00:1d:0d", "00:24:8d", "28:0d:fc", "2c:cc:44", "70:9e:29", "78:c8:81",
                  "bc:60:a7", "f8:46:1c", "f8:d0:ac", "00:d9:d1", "0c:fe:45", "04:5d:4b", "40:49:0f", "a8:e3:ee"]),
        ("LG", ["00:1c:62", "00:1e:75", "00:22:a9", "00:25:e5", "00:26:e2", "10:68:3f", "20:3d:bd", "2c:54:cf", "3c:cd:93", "48:59:29",
                "58:a2:b5", "60:e3:ac", "64:99:5d", "70:05:14", "74:a7:22", "88:36:6c", "a8:16:b2", "a8:23:fe", "b4:e6:2a", "c4:9a:02",
                "cc:fa:00", "f8:0c:f3"]),
        ("Synology", ["00:11:32", "90:09:d0"]),
        ("QNAP", ["24:5e:be"]),
        ("NVIDIA", ["00:04:4b", "48:b0:2d"]),
        ("Logitech", ["00:1f:20", "44:73:d6"]),
        ("Wyze", ["2c:aa:8e", "7c:78:b2"]),
        ("Tuya", ["10:d5:61", "7c:f6:66", "1c:90:ff", "d4:a6:51", "84:e3:42", "18:de:50", "50:8a:06", "84:7a:b6"]),
        ("Huawei", ["00:18:82", "00:1e:10", "00:25:9e", "00:46:4b", "04:bd:70", "08:19:a6", "0c:37:dc", "10:47:80", "18:c5:8a", "1c:1d:67",
                    "20:0b:c7", "24:09:95", "28:31:52", "2c:ab:00", "34:6b:d3", "38:bc:01", "3c:f8:08", "48:46:fb", "4c:1f:cc", "54:89:98",
                    "5c:7d:5e", "60:de:44", "70:72:3c", "78:d7:52", "80:fb:06", "88:11:96", "8c:34:fd", "a4:99:47", "ac:e2:15", "b4:15:13",
                    "c8:d1:5e", "d4:6a:a8", "e0:24:7f", "e4:68:a3", "f4:c7:14"]),
        ("Cisco", ["00:00:0c", "00:1a:a1", "00:1b:d4", "00:1e:13", "00:21:1b", "00:23:04", "00:26:0b", "2c:3f:38", "50:06:04", "58:97:1e",
                   "70:ca:9b", "88:75:56", "a0:cf:5b", "c0:62:6b", "f4:4e:05", "00:25:45", "34:bd:c8", "68:7f:74", "6c:50:4d", "bc:16:65"]),
        ("Linksys", ["00:0c:41", "00:12:17", "00:13:10", "00:14:bf", "00:16:b6", "00:18:39", "00:18:f8", "00:1a:70", "00:1c:10", "00:1d:7e",
                     "00:1e:e5", "00:21:29", "00:22:6b", "00:23:69", "00:25:9c", "20:aa:4b", "48:f8:b3", "58:6d:8f", "c0:c1:c0", "c0:56:27",
                     "14:91:82", "24:f5:a2", "30:23:03", "80:69:1a", "ba:9d:c1"]),
        ("D-Link", ["00:05:5d", "00:0d:88", "00:0f:3d", "00:11:95", "00:13:46", "00:15:e9", "00:17:9a", "00:19:5b", "00:1b:11", "00:1c:f0",
                    "00:1e:58", "00:21:91", "00:22:b0", "00:24:01", "00:26:5a", "14:d6:4d", "1c:7e:e5", "1c:af:f7", "1c:bd:b9", "28:10:7b",
                    "34:08:04", "5c:d9:98", "78:54:2e", "84:c9:b2", "90:94:e4", "a0:ab:1b", "b8:a3:86", "c4:a8:1d", "c8:be:19", "cc:b2:55",
                    "ec:ad:e0", "f0:7d:68", "fc:75:16"]),
        ("Sagemcom", ["00:1e:74", "00:26:91", "18:62:2c", "28:3b:82", "34:7a:60", "38:43:7d", "40:f2:01", "44:e9:dd", "48:00:33", "50:7e:5d",
                      "5c:b1:3e", "68:a3:78", "70:4f:b8", "7c:03:d8", "88:03:55", "90:4d:4a", "94:6a:b0", "a0:1b:29", "a4:b1:e9", "b0:4e:bf",
                      "b8:f8:53", "c0:ac:54", "cc:33:bb", "d0:6e:de", "d8:b6:b7", "e8:f1:b0", "e8:be:81", "f4:e4:ad", "f8:08:4f", "fc:b4:e6", "f8:6f:b0"]),
        ("Arris", ["00:1d:ce", "00:1d:cf", "00:1d:d0", "00:1d:d1", "00:1d:d2", "00:1d:d3", "00:1d:d4", "00:1d:d5", "00:1d:d6", "10:86:8c",
                   "14:ab:f0", "1c:1b:68", "20:3d:66", "24:76:7d", "2c:9e:5f", "34:1f:e4", "38:3f:b3", "3c:04:61", "3c:7a:8a", "4c:12:65",
                   "54:65:de", "58:23:8c", "5c:8f:e0", "70:5a:9e", "74:e7:c6", "78:71:9c", "80:f5:03", "84:e0:58", "90:c7:92", "94:87:7c",
                   "9c:34:26", "a0:c5:62", "a4:ed:4e", "a8:11:fc", "ac:b3:13", "b4:f2:e8", "c0:05:c2", "c8:aa:cc", "d4:ab:82", "e8:ed:05", "f8:2d:c0", "fc:91:14"]),
        ("Technicolor", ["00:1f:9f", "00:24:17", "00:26:44", "08:95:2a", "10:62:eb", "18:1b:eb", "1c:ab:c0", "30:91:8f", "34:08:bc", "38:72:c0",
                         "4c:17:eb", "60:38:e0", "64:7c:34", "78:71:9c", "80:29:94", "84:94:8c", "88:f7:c7", "a8:4e:3f", "ac:02:cf", "c0:3c:04",
                         "c4:ea:1d", "cc:03:fa", "d4:35:1d", "dc:0b:1a", "e4:ab:89", "e8:cc:18", "fc:94:e3"]),
        ("Virgin Media / Hitron", ["00:f7:6f", "70:b1:4e", "f0:d7:aa", "e4:c1:46", "cc:c9:eb", "14:5b:d1"]),
        ("BT", ["00:25:46", "18:62:2c", "60:38:e0", "c0:3c:04"]),
        ("Eero", ["f0:81:73"]),
    ]

    private static let index: [String: String] = {
        var m: [String: String] = [:]
        for (vendor, prefixes) in vendors { for p in prefixes where m[p] == nil { m[p] = vendor } }
        return m
    }()

    /// Normalised `aa:bb:cc:dd:ee:ff` or nil if malformed.
    public static func normalize(_ mac: String) -> String? {
        let parts = mac.lowercased().replacingOccurrences(of: "-", with: ":").split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 6 else { return nil }
        var out: [String] = []
        for p in parts {
            guard p.count >= 1, p.count <= 2, p.allSatisfy({ $0.isHexDigit }) else { return nil }
            out.append(p.count == 1 ? "0" + p : String(p))
        }
        return out.joined(separator: ":")
    }

    /// Locally administered bit set: randomised ("private") Wi-Fi address, VM, or software-defined MAC.
    public static func isLocallyAdministered(_ mac: String) -> Bool {
        guard let m = normalize(mac), let first = UInt8(m.prefix(2), radix: 16) else { return false }
        return first & 0x02 != 0
    }

    public static func vendor(for mac: String) -> String? {
        guard let m = normalize(mac) else { return nil }
        if let v = index[String(m.prefix(8))] { return v }
        return nil
    }

    public static var count: Int { index.count }
}

/// Guesses a device type from what the scan learned about it. Pure; fixture-testable.
public enum DeviceTypeGuesser {
    public static func guess(vendor: String?, hostname: String?, mdnsName: String?, model: String?, services: [String],
                             ssdpServer: String?, openPorts: [Int], isGateway: Bool) -> NetDeviceType {
        let name = ((hostname ?? "") + " " + (mdnsName ?? "") + " " + (model ?? "") + " " + (ssdpServer ?? "")).lowercased()
        let svc = Set(services.map { $0.lowercased() })
        let v = (vendor ?? "").lowercased()
        func has(_ s: String) -> Bool { name.contains(s) }

        if isGateway { return .router }
        // Explicit model strings (Apple _device-info TXT, SSDP SERVER).
        if has("macbook") { return .laptop }
        if has("imac") || has("macmini") || has("mac mini") || has("macpro") || has("mac studio") || has("macstudio") || has("mac1") || has("mac2") || has("mac,") { return .mac }
        if has("iphone") { return .iPhone }
        if has("ipad") { return .iPad }
        if has("appletv") || has("apple tv") || has("apple-tv") { return .appleTV }
        if has("homepod") || has("audioaccessory") { return .homePod }
        if has("watch") && v == "apple" { return .appleWatch }
        if has("raspberrypi") || has("raspberry") || v == "raspberry pi" { return .raspberryPi }
        if has("printer") || svc.contains("_ipp._tcp") || svc.contains("_printer._tcp") || svc.contains("_pdl-datastream._tcp") || svc.contains("_ipps._tcp") { return .printer }
        if has("camera") || has("ipc") || has("doorbell") || v == "hikvision" || v == "dahua" || v == "wyze" || v == "ring" { return has("doorbell") || v == "ring" ? .doorbell : .camera }
        if has("hue") || v == "philips hue" { return .smartLight }
        if has("sonos") || v == "sonos" { return .speaker }
        if has("roku") || v == "roku" || has("fire tv") || has("firetv") || has("chromecast") || has("shield") { return .streamingStick }
        if has("echo") || has("alexa") || has("google home") || has("nest hub") || has("nest mini") { return .voiceAssistant }
        if has("thermostat") || has("nest-learning") { return .thermostat }
        if has("playstation") || has("ps4") || has("ps5") || has("xbox") || has("nintendo") || has("switch") && v == "nintendo" || v == "nintendo" { return .gameConsole }
        if has("synology") || has("diskstation") || has("qnap") || has("nas") || v == "synology" || v == "qnap" { return .nas }
        if has("tv") && (v == "samsung" || v == "lg" || v == "sony") || svc.contains("_googlecast._tcp") && (v == "samsung" || v == "lg") || has("bravia") || has("webos") { return .tv }
        if svc.contains("_googlecast._tcp") || svc.contains("_airplay._tcp") && v != "apple" { return .streamingStick }
        if has("android") || has("galaxy") || has("pixel") || has("oneplus") { return .androidPhone }
        if has("plug") || has("socket") || has("outlet") || has("kasa") { return .smartPlug }
        if has("unifi") || has("u6-") || has("uap") || has("access point") || has("eero") { return .accessPoint }
        if has("router") || has("archer") || has("nighthawk") || has("linksys") || has("hub 3") || has("smart hub") || has("home hub") { return .router }
        // Vendor-only guesses.
        switch v {
        case "apple":
            if svc.contains("_companion-link._tcp") && !svc.contains("_smb._tcp") && !svc.contains("_ssh._tcp") { return .iPhone }
            if svc.contains("_smb._tcp") || svc.contains("_ssh._tcp") || svc.contains("_afpovertcp._tcp") || svc.contains("_rfb._tcp") { return .mac }
            if svc.contains("_airplay._tcp") || svc.contains("_raop._tcp") { return .appleTV }
            return .iPhone
        case "espressif", "tuya": return .iot
        case "amazon": return .voiceAssistant
        case "google": return .voiceAssistant
        case "samsung", "xiaomi", "huawei": return .phone
        case "hp", "brother", "canon", "epson": return .printer
        case "tp-link", "netgear", "asus", "d-link", "linksys", "sagemcom", "arris", "technicolor", "virgin media / hitron", "bt", "eero", "ubiquiti", "cisco": return .accessPoint
        case "microsoft", "dell", "lenovo", "intel": return .computer
        case "sony", "lg": return .tv
        case "nvidia": return .streamingStick
        case "logitech": return .iot
        default: break
        }
        if svc.contains("_smb._tcp") || svc.contains("_ssh._tcp") || svc.contains("_rdp._tcp") || openPorts.contains(3389) { return .computer }
        if svc.contains("_hap._tcp") || svc.contains("_homekit._tcp") { return .iot }
        if openPorts.contains(554) { return .camera }
        if openPorts.contains(9100) { return .printer }
        return .unknown
    }
}
