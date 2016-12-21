import os
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import logging
from logging import NullHandler
import sqlite3
import base64
from random import choice

logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())

hash_alg = 'sha256'
pw_iter = 100000

pwchars = '!#%+23456789:=?@ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class CollisionException(Exception):
    """When a location/username combination already exists"""
    pass

def create_database(filepath):
    conn = sqlite3.connect(filepath)
    c = conn.cursor()

    try:
        c.execute('CREATE TABLE IF NOT EXISTS passwd (location text, username text, encrypted_password text, encrypted_notes text, UNIQUE(location, username))')
        c.execute('CREATE TABLE IF NOT EXISTS master (id integer primary key, salt text, password_hash text)')

        conn.commit()
    except:
        conn.rollback()

    conn.close()

def open_database(filepath):
    conn = sqlite3.connect(filepath)

    return conn

def encrypt_data(key,byte_array):
    f = Fernet(key)
    result = f.encrypt(byte_array)

    return result

def decrypt_data(key,byte_array):
    f = Fernet(key)
    result = f.decrypt(byte_array)

    return result

def generate_encryption_key(password, salt):
    bsalt = base64.urlsafe_b64decode(salt)
    key = pbkdf2_hmac(hash_alg, password.encode('utf-8'), bsalt, pw_iter)

    return base64.urlsafe_b64encode(key)

def generate_password_hash(password, salt):
    bsalt = base64.urlsafe_b64decode(salt)
    key = pbkdf2_hmac(hash_alg, password.encode('utf-8'), bsalt, pw_iter)

    return base64.urlsafe_b64encode(key[:16])

def generate_password(length, charset=pwchars):
    characters = [choice(charset) for i in range(length)]

    return ''.join(characters)

def generate_salt():
    return base64.urlsafe_b64encode(os.urandom(32))

def generate_password_and_save(db_conn, key, location, username, length, charset=pwchars):
    password = generate_password(length, charset)

    c = db_conn.cursor()
    encrypted_password = encrypt_data(key, password.encode('utf-8'))

    try:
        c.execute('INSERT OR ABORT INTO passwd (location, username, encrypted_password) VALUES (?,?,?)',[location, username, encrypted_password])
        db_conn.commit()
    except sqlite3.IntegrityError:
        raise CollisionException('That location/username combination already exists')

    return password

def generate_password_and_overwrite(db_conn, key, location, username, length, charset=pwchars):
    password = generate_password(length, charset)

    c = db_conn.cursor()
    encrypted_password = encrypt_data(key, password.encode('utf-8'))

    c.execute('UPDATE OR ABORT passwd SET encrypted_password=? WHERE location=? AND username=?',[encrypted_password, location, username])
    db_conn.commit()

    return password

def set_password_and_notes(db_conn, key, location, username, password, notes):
    c = db_conn.cursor()

    if password is None:
        encrypted_password=None
    else:
        encrypted_password = encrypt_data(key, password.encode('utf-8'))

    if notes is None:
        encrypted_notes = None
    else:
        encrypted_notes = encrypt_data(key, notes.encode('utf-8'))

    c.execute('INSERT OR REPLACE INTO passwd (location, username, encrypted_password, encrypted_notes) VALUES (?,?,?,?)',
            [location, username, encrypted_password, encrypted_notes])
    db_conn.commit()

def retrieve_password_and_notes(db_conn, key, location, username):
    c = db_conn.cursor()
    c.execute('SELECT encrypted_password, encrypted_notes FROM passwd WHERE location=? AND username=?', [location, username])
    row = c.fetchone()

    if row is None:
        return (None, None)

    if row[0] is None:
        password = None
    else:
        password = decrypt_data(key, row[0]).decode('utf-8')

    if row[1] is None:
        notes = None
    else:
        notes = decrypt_data(key, row[1]).decode('utf-8')

    return password, notes

def append_note(db_conn, key, location, username, note):
    c = db_conn.cursor()
    c.execute('SELECT encrypted_notes FROM passwd WHERE location=? AND username=?', [location, username])
    row = c.fetchone()

    if row is None or row[0] is None:
        encrypted_note = encrypt_data(key, note.encode('utf-8'))
    else:
        old_note = decrypt_data(key, row[0]).decode('utf-8')
        new_note = '\n'.join([old_note, note])
        encrypted_note = encrypt_data(key, new_note.encode('utf-8'))

    if row is None:
        c.execute('INSERT OR REPLACE INTO passwd (location, username, encrypted_notes) VALUES (?,?,?)', [location, username, encrypted_note])
    else:
        c.execute('UPDATE OR ABORT passwd SET encrypted_notes=? WHERE location=? AND username=?', [encrypted_note, location, username])
    db_conn.commit()

def set_master_password(db_conn, password):
    c = db_conn.cursor()
    
    c.execute('SELECT * FROM master')
    row = c.fetchone()

    if row is not None:
        raise CollisionException('Master password is already set. Use update instead')

    salt = generate_salt()

    pwhash = generate_password_hash(password, salt)
    key = generate_encryption_key(password, salt)

    c.execute('INSERT INTO master (salt, password_hash) VALUES (?,?)',[salt, pwhash])
    db_conn.commit()

    return key

def is_master_password_set(db_conn):
    c = db_conn.cursor()
    c.execute('SELECT * FROM master')
    row = c.fetchone()

    if row is None:
        result = False
    else:
        result = True

    return result

def update_master_password(db_conn, oldpassword, newpassword):
    oldkey = verify_master_password(db_conn, oldpassword)

    if oldkey is None:
        return None

    salt = generate_salt()
    pwhash = generate_password_hash(newpassword, salt)
    newkey = generate_encryption_key(newpassword, salt)

    c = db_conn.cursor()
    c.execute('INSERT INTO master (salt, password_hash) VALUES (?,?)',[salt, pwhash])
    db_conn.commit()

    for location, username in item_generator(db_conn):
        password, notes = retrieve_password_and_notes(db_conn, oldkey, location, username)
        set_password_and_notes(db_conn, newkey, location, username, password, notes)

    return newkey

def verify_master_password(db_conn, password):
    c = db_conn.cursor()

    c.execute('SELECT salt, password_hash FROM master ORDER BY id DESC')
    row = c.fetchone()

    if row is None:
        raise KeyError('Master password not found')

    salt = row[0]
    saved_pw_hash = row[1]

    calculated_pw_hash = generate_password_hash(password, salt)

    if saved_pw_hash==calculated_pw_hash:
        key = generate_encryption_key(password, salt)
    else:
        key = None

    return key

def item_generator(db_conn, location=None):
    c = db_conn.cursor()

    if location is None:
        c.execute('SELECT location, username FROM passwd')
    else:
        c.execute('SELECT username FROM passwd WHERE location=?', [location])

    allrows = c.fetchall()

    for row in allrows:
        yield row
