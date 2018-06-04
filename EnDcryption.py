#!/usr/bin/python3
import random
import time
from pyLogger import Log
from function_timer import measure_time
import string
import os
import sys
import getopt
from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog, tkMessageBox
Log.setLoglvl(60)

def encrypt_line(_line, _encoding, _seed, encoded_count=None):
    erndm = random.Random()
    erndm.seed(_seed)
    encrypted_line = ''
    for char in _line:
        char_keys = _encoding[erndm.randint(0,3)]
        encoded_key = char_keys[char]
        if encoded_count != None:
            if encoded_key not in encoded_count:
                encoded_count[encoded_key] = 1
            else:
                encoded_count[encoded_key] += 1
        encrypted_line += char_keys[char]
    if encoded_count:
        return encrypted_line, encoded_count
    else:
        return encrypted_line

def print_dict(_dict):
    for k, val in _dict.items():
        print k, ':', val

def msg_box(_title, _description):
    tkMessageBox.showinfo(_title, _description)
  
def dev_mode():
    def usage():
        print ('    Cannot do both in one run, choose to Encrypt or Decrypt Documents:')
        print ('\t -e : --encrypt \t| File to encrypt. (Filename/FilePath)')
        print ('\t -d : --decrypt \t| File to decrypt (Requires Key). (Filename/FilePath)')
        print ('\t -k : --key \t\t| Key to encrypted document. (Filename/FilePath)')
        print ('\t -s : --stdout \t\t| (Optional) Send Debug logs to StdOut.')
        print ('\t -D : --debuglvl \t| (Optional | Default=60) Change Debug lvls between (10-60).')
    checkflag = 0
    set_encrypt = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'D:d:e:k:hs')  # f is the path of the scenario config
    except Exception as e:
        print (e)
        usage()
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-D", "--debuglvl"):
            debuglvl = int(a)
            Log.setLoglvl(debuglvl)
            print ("Logging Mode: ON")
        elif o in ("-e", "--encrypt"):
            set_encrypt = True
            encrypt_filename = a
        elif o in ("-d", "--decrypt"):
            checkflag += 1
            decrypt_filename = a
        elif o in ("-s", "--stdout"):
            print ('Logging to STDOUT!')
            Log.logStdOut = True
        elif o in ("-k", "--key"):
            checkflag += 1
            key_file = a
    '''
    if not opts:
        action = str(raw_input('Encrypt or Decrypt? (e/d): '))
        if action == 'e':
            encrypt_filename = str(raw_input('File name or file path for encryption (ex. "C:\\folder\\text.txt"): '))
            print('Start Encryption...')
            encrypt_file(encrypt_filename)
            print('Finished Encrypting...')
        elif action == 'd':
            decrypt_filename = str(raw_input('File name or file path for decryption (ex. "C:\\folder\\text_encrypted.dat"): '))
            key_file = str(raw_input('Key (File name or file path) for decryption (ex. "C:\\folder\\key.dat"): '))
            decrypt_file(key_file, decrypt_filename)
        else:
            print('Please Answer with "e" or "d"! Or run with command line arguments!')
            time.sleep(5)
            sys.exit(2)
    else:
    '''
    if set_encrypt:
        print('Start Encryption...')
        encrypt_file(encrypt_filename)
        print('Finished Encrypting...')
        return None
    else:
        if checkflag != 2:
            print ('Missing Encryption Key!')
            usage()
            sys.exit(2)
        ##### decrypt file ######
        else:
            decrypt_file(key_file, decrypt_filename)
            return 

def encrypt_key(_key, f_ext):
    converted_key_string = ''
    _public_key = []
    char_keys = []
    ids = []
    _encoding = [{}, {}, {}, {}]
    _private_key = [[326, 4, 1527194773, 123], [714, 4, 1527194777, 123], [831, 5, 1527194781, 123], [189, 4, 1527194783, 123]]
    
    for number in range(123):
        new_char = chr(number)
        if new_char not in char_keys:
            char_keys.append(new_char)
            
    for k in _key:
        for number in k:
            converted_key_string += str(number) + ' '
        _public_key.append(converted_key_string)
        converted_key_string = ''
    _public_key.append(f_ext)
    
    for char in char_keys:
        for ind in range(len(_private_key)):
            _private_key[ind][0] += 1
            eval_check = gen_evalue(_private_key[ind],_private_key[ind][0], ids)
            if eval_check in ids:
                Log.CRITICAL('SAME ID during encryption: ', eval_check)
            else:
                ids.append(eval_check)
            _encoding[ind][char] = eval_check
    
    with open('key.dat', 'w') as _kfile:
        _kfile.write('')

    with open('key.dat', 'a') as _kfile:
        for _pkey in _public_key:
            eline = encrypt_line(_pkey, _encoding, 326)
            _kfile.write(eline)

def decrypt_key(_key_file):
    dict_char = []
    ids = []
    encoding = {}
    _key = []
    all_keys = []
    new_key_counter =0
    _private_key = [[326, 4, 1527194773, 123], [714, 4, 1527194777, 123], [831, 5, 1527194781, 123], [189, 4, 1527194783, 123]]
    for number in range(_private_key[0][3]):
        new_char = chr(number)
        if new_char not in dict_char:
            dict_char.append(new_char)

    #Get Encoded Values
    for char in dict_char:
        for ind in range(len(_private_key)):
            _private_key[ind][0] += 1
            val = gen_evalue(_private_key[ind],_private_key[ind][0], ids)
            if val in ids:
                Log.ERROR('SAME ID in Decryption (private key): ',val)
                Log.ERROR('Value Assigned to: ', encoding[val])
            else:
                ids.append(val)
            encoding[val] = char

    #Read Encrypted File and Decrypt
    found_entry = False
    found_err = False
    try:
        with open(_key_file, 'r') as refile:
            read_file = refile.read()
            key_values = ''
            for ind in range(len(read_file)):
                if ind%8 == 0:
                    if read_file[ind-8:ind] in encoding:
                        key_values += encoding[read_file[ind-8:ind]]
                        found_entry = True
                    else:
                        if ind != 0:
                            found_err = True
            if not found_entry and found_err:
                print("WRONG PRIVATE KEY!!!!")
                msg_box("Error", "WRONG PRIVATE KEY!!!!")
                return None
            elif found_entry and found_err:
                print("Cannot find correct encoding for private key")
                msg_box("Error","Cannot find correct encoding for private key")
                return None
            else:    
                key_values += encoding[read_file[-8:]]
        split_kvalues = key_values.split()
        f_ext = split_kvalues[-1]
        for val in range(len(split_kvalues)-1):
            new_key_counter += 1
            _key.append(int(split_kvalues[val]))
            if new_key_counter == 4:
                all_keys.append(_key)
                _key = []
                new_key_counter = 0
        return all_keys, f_ext
                
    except IOError as e:
        Log.CRITICAL(e)
        print('Cannot find encrypted file: ' + encrypted_file)
        msg_box("Error", 'Cannot find encrypted file: ' + encrypted_file)
        time.sleep(5)
        sys.exit(2)
         
def encrypt_file(_filename):
    largest_charnumber = 0
    encrypted_keys = []
    ids = []
    encoded_count = {}
    char_keys = []
    char_count = {}
    _filelines = []
    _encoding = [{}, {}, {}, {}]
    file_ext = _filename[_filename.find('.'):]
    with open('key.dat', 'w') as _kfile:
        _kfile.write('')
        
    try:
        with open(_filename, 'rb') as _file:
            for line in _file:
                _filelines.append(line)
                
    except IOError as e:
        print("Cannot find file to encrypt: " + _filename)
        msg_box('Error','Cannot find file to encrypt: ' + _filename)
        Log.CRITICAL(e)
        time.sleep(5)
        sys.exit(2)
            
    for line in _filelines:
        for char in line:
            if char not in char_count:
                char_count[char] = 1
            else:
                char_count[char] += 1
            if largest_charnumber < ord(char):
                largest_charnumber = ord(char)
                
    for number in range(largest_charnumber+1):
        new_char = chr(number)
        if new_char not in char_keys:
            char_keys.append(new_char)

    for i in range(4):
        encrypted_keys.append(generate_ekey(len(char_keys)))

    first_seed = encrypted_keys[0][0]
    erndm = random.Random()
    erndm.seed(first_seed)

    #Encrypt Key
    encrypt_key(encrypted_keys, file_ext)

    #Encode characters
    for char in char_keys:
        for ind in range(len(encrypted_keys)):
            encrypted_keys[ind][0] += 1
            eval_check = gen_evalue(encrypted_keys[ind],encrypted_keys[ind][0], ids)
            if eval_check in ids:
                Log.CRITICAL('SAME ID during encryption: ', eval_check)
            else:
                ids.append(eval_check)
            _encoding[ind][char] = eval_check
            
    #Write to new file
    _filename_wo_ext = _filename[:_filename.find('.')]
    new_filename = _filename_wo_ext + '_encrypted.dat'

    with open(new_filename, 'wb') as _nfile:
        for line in _filelines:
            eline, encoded_count = encrypt_line(line, _encoding, first_seed, encoded_count)
            _nfile.write(eline)

#@measure_time('Decrypt_Time')    
def decrypt_file(key_file, encrypted_file):
    dict_char = []
    ids = []
    encoding = {}
    
    #Decrypt Key
    e_key, file_ext = decrypt_key(key_file)
    if not e_key:
        return
    
    #Get characters to map
    for number in range(e_key[0][3]):
        new_char = chr(number)
        if new_char not in dict_char:
            dict_char.append(new_char)

    #Get Encoded Values
    for char in dict_char:
        for ind in range(len(e_key)):
            e_key[ind][0] += 1
            val = gen_evalue(e_key[ind],e_key[ind][0], ids)
            if val in ids:
                Log.ERROR('SAME ID in Decryption: ',val)
                Log.ERROR('Value Assigned to: ', encoding[val])
            else:
                ids.append(val)
            encoding[val] = char
            
    #Read Encrypted File and Decrypt
    found_entry = False
    found_err = False
    try:
        with open(encrypted_file, 'r') as refile:
            read_file = refile.read()
            new_file = ''
            for ind in range(len(read_file)):
                if ind%8 == 0:
                    if read_file[ind-8:ind] in encoding:
                        new_file += encoding[read_file[ind-8:ind]]
                        found_entry = True
                    else:
                        if ind != 0:
                            found_err = True
                            Log.WARNING('Not in here: ', read_file[ind-8:ind])

            if not found_entry and found_err:
                Log.WARNING('Wrong Key')
                print("WRONG ENCRYPTION KEY!!!!")
                msg_box('Error', "WRONG ENCRYPTION KEY!!!!")
            elif found_entry and found_err:
                print("Cannot find correct encoding... (Possibly Wrong Encryption Key). (Turn on Logging to debug)")
                msg_box('Error', "Cannot find correct encoding... (Possibly Wrong Encryption Key). (Turn on Logging to debug)")
            else:    
                new_file += encoding[read_file[-8:]]
    except IOError as e:
        Log.CRITICAL(e)
        print('Cannot find encrypted file: ' + encrypted_file)
        msg_box('Error','Cannot find encrypted file: ' + encrypted_file) 
        time.sleep(5)
        sys.exit(2)
    new_filename = 'DCDocument_'+str(int(time.time()))+ file_ext
    with open(new_filename, 'wb') as dfile:
        dfile.write(new_file)

def gen_evalue(_ekey,_eseed, ids):
    ekey_value = ''
    _rnd = random.Random()
    _rnd.seed(_eseed)
    length = 8
    tval = str(_ekey[2])
    check = False
    e_tval = int(tval[-(_rnd.randint(3, _ekey[1])):])
    while True:
        for i in range(length):
            choice = abs(int(((i*i) + i*_ekey[1] - float(_eseed))/float(i+1)))
            if choice%4 == 0:
                val = str(_rnd.randrange(1, e_tval))
                ekey_value += str(_rnd.randrange(2, e_tval))
            else:
                val = _rnd.choice(string.letters)
                ekey_value += val
        if len(ekey_value) > 8:
            ekey_value = ekey_value[:8]
        if ekey_value in ids:
            check = True
            ekey_value = ''
            _eseed += 1
            _ekey[1] += 1
        else:
            break
    return ekey_value

#@measure_time('Key_Time')
def generate_ekey(num_of_char):
    time.sleep(random.randint(1,4))
    _startseed = random.randrange(1,1000)
    tval = int(time.time())
    tval_end = random.randint(4,5)
    return [_startseed, tval_end, tval, num_of_char]

class App:
    def __init__(self, master):
        frame = Frame(master)
        frame.pack(side=BOTTOM)
        self.lb1 = Label(master, text="Select Option...")
        self.lb1.pack(side=TOP)
        self.button = Button(
            frame, text="QUIT", fg="red", command=master.destroy
            )
        self.button.pack(side=RIGHT)

        self.encrypt = Button(frame, text="Encrypt",
                              command=lambda:encrypt_ui(self.lb1))
        self.encrypt.pack(side=LEFT)

        self.decrypt = Button(frame, text="Decrypt",
                              command=lambda:decrypt_ui(self.lb1))
        self.decrypt.pack(side=RIGHT)
        
        self.lb1.config(text="Select Option...")


def encrypt_ui(_label):
    cwd = os.getcwd()
    _label.config(text="Encrypting...")
    filename = tkFileDialog.askopenfilename(initialdir = cwd,
    title = "Select file",filetypes = (("txt files","*.txt"),
                                       ("all files","*.*")))
    if not filename:
        msg_box("Missing File", "Missing File to Encrypt!")
        return _label.config(text="Select Option...")
    
    encrypt_file(filename)
    _label.config(text="Finished Encryption!")
    msg_box("Completed", "Finished Encryption!")
    
def decrypt_ui(_label):
    cwd = os.getcwd()
    _label.config(text="Decrypting...")

    filename = tkFileDialog.askopenfilename(initialdir = cwd,
    title = "Select Decryption File",filetypes =(("dat files","*.dat"),))
    if not filename:
        msg_box("Missing File", "Missing Decryption File!")
        return _label.config(text="Select Option...")
                              
    key_filename = tkFileDialog.askopenfilename(initialdir = cwd,
    title = "Select Key File",filetypes = (("dat files","*.dat"),))
    if not key_filename:
        msg_box("Missing File", "Missing Decryption File!")
        return _label.config(text="Select Option...")
    
    decrypt_file(key_filename, filename)
    _label.config(text="Finished Decryption!")
    msg_box("Completed", "Finished Decryption!")

    
if __name__ == '__main__':
    if sys.argv[1:]:
        dev_mode()
    else:
        root = Tk()
        root.title("EnDcryption")
        root.geometry("200x50")
        root.resizable(0, 0)
        app = App(root)
        root.mainloop()
        

