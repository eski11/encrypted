import unittest
from prepare_release import rewrite

class ReleaseRewriteTests(unittest.TestCase):
    def test_preserves_json_literals_comments_and_framework_apis(self):
        source = 'struct Vault: Codable { let key = "Vault"; /* Vault */ var item: Vault?; func f() { print("Vault \\(item)") } } // Vault'
        result = rewrite(source, {'Vault': 'Qabc'})
        self.assertIn('struct Qabc: Codable', result)
        self.assertIn('var item: Qabc?', result)
        self.assertIn('"Vault"', result)
        self.assertIn('/* Vault */', result)
        self.assertIn('// Vault', result)
        self.assertIn('"Vault \\(item)"', result)

if __name__ == '__main__':
    unittest.main()
