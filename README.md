# encrypter
encrypter tiene como finalidad encriptar y desencriptar archivos utilizando los algoritmos [AES](https://github.com/B-Con/crypto-algorithms/blob/master/aes.c) o [Blowfish](https://github.com/B-Con/crypto-algorithms/blob/master/blowfish.c) usando claves de 128, 192 ó 256 bits, que son generadas por el algoritmo de hashing [SHA256](https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c) mediante el ingreso de una frase secreta.

# Requerimientos.
- [x] make <br>
- [x] gcc

# Compilación.
```bash
$ make
```

# Uso.
* ## Menú de ayuda.
```console
$ ./encrypter -h
```
output:
```console
encrypter encripta o desincripta un archivo usando los algoritmos AES o BLOWFISH.
uso:
./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>
./encrypter -h
Opciones:
-h                      Ayuda, muestra este mensaje.
-d                      Desincripta el archivo en lugar de encriptarlo.
-k <passphrase>         Especifica la frase de encriptación.
-a <algo>               Especifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]
-b <bits>               Especifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]
```

* ## Encriptación.
  ### 1. Clave.
    - Es obligatorio el ingreso de una clave de encriptación con la opción -k.
    - Para ingresar frases largas se ingresa entre comillas.
  
  ### 2. Algoritmo criptográfico.
    - Con la opción -a se especifica el algoritmo a utilizar.
    - Por defecto es AES.
  
  ### 3. Cantidad de bits de clave.
    - Con la opción -b se especifica la cantidad de bits para la clave.
    - Por defecto son 128.
   
  ### Ejemplo.
```console
$ ./encrypter -a blowfish -b 256 -k "Clave de encriptación larga" archivonormal.zip
```
* ## Desencriptación.
   - Es obligatorio el ingreso de una clave de encriptación con la opción -k.
   - Solo se pueden desencriptar los archivos .enc
   - Se descartan los argumentos de las opciones -a y -b.
   - Encrypter analiza con que algoritmo y la cantidad de bits de clave con la que fue encriptado el archivo.
   
   ### Ejemplo.
```console
$ ./encrypter -d -k "Clave de encriptación larga" archivonormal.zip.enc
```
# Créditos.
La solución se creó tomando los algoritmos de criptografía [B-Con/crypto-algorithms](https://github.com/B-Con/crypto-algorithms).
