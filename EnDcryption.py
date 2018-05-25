#!/usr/bin/python3
import random
import time
from pyLogger import Log
import string
import os
import sys
import getopt
Log.setLoglvl(60)

def encrypt_line(_line, _encoding, _seed):
    erndm = random.Random()
    erndm.seed(_seed)
    encrypted_line = ''
    for char in _line:
        char_keys = _encoding[erndm.randint(0,3)]
        encrypted_line += char_keys[char]
    return encrypted_line

def print_dict(_dict):
    for k, val in _dict.items():
        print k, ':', val
  
def main():
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
                return decrypt_file(key_file, decrypt_filename)

def encrypt_key(_key):
    converted_key_string = ''
    _public_key = []
    char_keys = []
    ids = []
    _encoding = [{}, {}, {}, {}]
    _private_key = [[326, 4, 1527194773, 58], [714, 4, 1527194777, 58], [831, 5, 1527194781, 58], [189, 4, 1527194783, 58]]
    
    for number in range(58):
        new_char = chr(number)
        if new_char not in char_keys:
            char_keys.append(new_char)
            
    for k in _key:
        for number in k:
            converted_key_string += str(number) + ' '
        _public_key.append(converted_key_string)
        converted_key_string = ''
    
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
    _private_key = [[326, 4, 1527194773, 58], [714, 4, 1527194777, 58], [831, 5, 1527194781, 58], [189, 4, 1527194783, 58]]
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
            elif found_entry and found_err:
                print("Cannot find correct encoding for private key")
            else:    
                key_values += encoding[read_file[-8:]]
        split_kvalues = key_values.split()
        for val in range(len(split_kvalues)):
            new_key_counter += 1
            _key.append(int(split_kvalues[val]))
            if new_key_counter == 4:
                all_keys.append(_key)
                _key = []
                new_key_counter = 0
        return all_keys
                
    except IOError as e:
        Log.CRITICAL(e)
        print('Cannot find encrypted file: ' + encrypted_file)
        time.sleep(5)
        sys.exit(2)
            
def encrypt_file(_filename):
    largest_charnumber = 0
    encrypted_keys = []
    ids = []
    char_keys = []
    _filelines = []
    _encoding = [{}, {}, {}, {}]
    
    with open('key.dat', 'w') as _kfile:
        _kfile.write('')
        
    try:
        with open(_filename, 'r') as _file:
            for line in _file:
                _filelines.append(line)
    except IOError as e:
        print("Cannot find file to encrypt: " + _filename)
        Log.CRITICAL(e)
        time.sleep(5)
        sys.exit(2)
        
    for line in _filelines:
        for char in line:
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
    encrypt_key(encrypted_keys)

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
    new_filename = _filename[:-4] + '_encrypted.dat'

    with open(new_filename, 'w') as _nfile:
        for line in _filelines:
            eline = encrypt_line(line, _encoding, first_seed)
            _nfile.write(eline)


    
def decrypt_file(key_file, encrypted_file):
    dict_char = []
    ids = []
    encoding = {}
    
    #Decrypt Key
    e_key = decrypt_key(key_file)
    
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
            elif found_entry and found_err:
                print("Cannot find correct encoding... (Possibly Wrong Encryption Key). (Turn on Logging to debug)")
            else:    
                new_file += encoding[read_file[-8:]]
    except IOError as e:
        Log.CRITICAL(e)
        print('Cannot find encrypted file: ' + encrypted_file)
        time.sleep(5)
        sys.exit(2)
    new_filename = 'DCDocument_'+str(int(time.time()))+'.txt'
    with open(new_filename, 'w') as dfile:
        dfile.write(new_file)
    print('Decryption Complete!')
    return new_filename

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

def generate_ekey(num_of_char):
    time.sleep(random.randint(1,4))
    _startseed = random.randrange(1,1000)
    tval = int(time.time())
    tval_end = random.randint(4,5)
    return [_startseed, tval_end, tval, num_of_char]
    
if __name__ == '__main__':
    fname = main()
    #encrypt_key([[371, 4, 1527194082, 151], [208, 5, 1527194085, 151], [802, 5, 1527194086, 151], [189, 5, 1527194090, 151]])
    #encrypt_file('test_text2.txt')

    #fname = 'DCDocument_1526996198.txt'
    '''
    if fname:
        with open('test_text.txt', 'r') as file1:
            read_file1 = file1.read()
        with open(fname, 'r') as file2:
            read_file2 = file2.read()

        if read_file1 == read_file2:
            print 'TRUE'
        else:
            print 'FALSE'
    '''

