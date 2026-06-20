import unittest
import xml.etree.ElementTree as ET
from throttlegear.crypto import get_key_and_iv
from throttlegear.xml_processor import decrypt_xml, encrypt_xml

class TestXmlProcessor(unittest.TestCase):
    def test_xml_encryption_decryption_roundtrip(self):
        # Create a mock XML configuration tree
        root = ET.Element("ThrottlePluginConfig", {
            "MinLoaderVersion": "5.7.7.0",
            "ModelName": "G614PR",
            "Version": "1.0.5",
            "Type": "NB",
            "Cryptography": "Decrypted"
        })
        child1 = ET.SubElement(root, "Ryzen", {"Device": "CPU"})
        child2 = ET.SubElement(root, "RyzenCPUSettings", {"IsEnabled": "True"})
        child2.text = "Some internal settings content"
        
        # Derive Key & IV
        key, iv = get_key_and_iv("G614PR", "1.0.5", "NB")
        
        # 1. Encrypt the XML
        encrypt_xml(root, key, iv)
        self.assertEqual(root.attrib["Cryptography"], "Encrypted")
        self.assertEqual(len(root), 2)
        for elem in root:
            self.assertTrue(elem.tag.endswith("EncryptedData"))
            
        # 2. Decrypt it back
        decrypt_xml(root, key)
        self.assertEqual(root.attrib["Cryptography"], "Decrypted")
        self.assertEqual(len(root), 2)
        
        # Check child tags and text content are restored exactly
        self.assertEqual(root[0].tag, "Ryzen")
        self.assertEqual(root[0].attrib["Device"], "CPU")
        self.assertEqual(root[1].tag, "RyzenCPUSettings")
        self.assertEqual(root[1].attrib["IsEnabled"], "True")
        self.assertEqual(root[1].text, "Some internal settings content")

if __name__ == "__main__":
    unittest.main()
