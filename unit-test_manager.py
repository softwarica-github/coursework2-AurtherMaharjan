import unittest
from unittest.mock import patch
import os
import shutil
import tempfile
import secrets
from modified_password_manager1 import *
from modified_password_manager1 import _derive_key
from modified_password_manager1 import App

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.environ['USER'] = 'test_user'
        os.mkdir(os.path.join(self.temp_dir, 'password_manager'))
        os.mkdir(os.path.join(self.temp_dir, 'password_manager', 'content'))
        os.mkdir(os.path.join(self.temp_dir, 'password_manager', 'content', 'accounts'))
        os.mkdir(os.path.join(self.temp_dir, 'password_manager', 'logins'))
        with open(os.path.join(self.temp_dir, 'password_manager', 'logins', 'test_login.txt'), 'w') as f:
            f.write('')
        if hasattr(self, 'app'):
            self.app.root.destroy()
        self.app = App()


        
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        self.app.root.destroy()

        
    def test_derive_key(self):
        password = b'test_password'
        salt = secrets.token_bytes(16)
        key = _derive_key(password, salt)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 44)
        
    def test_password_encrypt_and_decrypt(self):
        message = b'test_message'
        password = 'test_password'
        encrypted = password_encrypt(message, password)
        decrypted = password_decrypt(encrypted, password)
        self.assertEqual(message, decrypted)
        
    @patch('builtins.input', side_effect=['test_login', 'test_password'])
    def test_getLogin(self, mock_input):
        app = App()
        app.getLogin()
        self.assertTrue(app.loggedBefore)
        
    @patch('builtins.input', side_effect=['test_login', 'test_password'])
    def test_getPassword(self, mock_input):
        app = App()
        app.getPassword()
        self.assertTrue(app.loggedBefore)
        
    def test_showLoginPage(self):
        app = App()
        app.showLoginPage()
        self.app.showLoginPage()
        app.root.protocol("WM_DELETE_WINDOW", lambda: app.root.destroy())
        self.assertEqual(app.loginEntry.winfo_x(), 170)
        self.assertEqual(app.loginEntry.winfo_y(), 200)
        self.assertEqual(app.passwordEntry.winfo_x(), 170)
        self.assertEqual(app.passwordEntry.winfo_y(), 250)
        self.assertEqual(app.submitLoginButton.winfo_x(), 330)
        self.assertEqual(app.submitLoginButton.winfo_y(), 200)
        self.assertEqual(app.registerButton.winfo_x(), 330)
        self.assertEqual(app.registerButton.winfo_y(), 250)


        
    @patch('builtins.input', side_effect=['', 'test_password'])
    def test_getLogin_type_login(self, mock_input):
        app = App()
        app.getLogin()
        self.assertEqual(app.loginEntry.winfo_x(), 170)
        self.assertEqual(app.loginEntry.winfo_y(), 200)
        self.assertEqual(app.passwordEntry.winfo_x(), 170)
        self.assertEqual(app.passwordEntry.winfo_y(), 250)
        self.assertEqual(app.typeLoginAlert.winfo_x(), 160)
        self.assertEqual(app.typeLoginAlert.winfo_y(), 280)
        
    @patch('builtins.input', side_effect=['test_nonexistent_login', 'test_password'])
    
    def test_getLogin_nonexistent_login(self, mock_input):
        app = App()
        app.getLogin()
        self.assertEqual(app.loginEntry.winfo_x(), 170)
        self.assertEqual(app.loginEntry.winfo_y(), 200)
        self.assertEqual(app.passwordEntry.winfo_x(), 170)
        self.assertEqual(app.passwordEntry.winfo_y(), 250)
        self.assertEqual(app.wrongLoginAlert.winfo_x(), 130)
        self.assertEqual(app.wrongLoginAlert.winfo_y(), 280)
        self.assertEqual(app.wrongLoginAlert.cget('text'), 'Login does not exist.')
        self.assertFalse(app.loggedBefore)
    def test_password_decrypt(self):
        # Test case 1: Correct password and token
        message = b'Test message'
        password = 'Test password'
        token = password_encrypt(message, password)
        decrypted_message = password_decrypt(token, password)
        self.assertEqual(decrypted_message, message)

        # Test case 2: Incorrect password
        message = b'Test message'
        password = 'Test password'
        token = password_encrypt(message, password)
        incorrect_password = 'Incorrect password'
        with self.assertRaises(Exception):
            password_decrypt(token, incorrect_password)

        # Test case 3: Invalid token
        password = 'Test password'
        invalid_token = b'invalid token'
        with self.assertRaises(Exception):
            password_decrypt(invalid_token, password)
            
if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)




    
