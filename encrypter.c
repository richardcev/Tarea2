#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>


//Librerías para encriptación y hashing.
#include "blowfish.h"
#include "sha256.h"
#include "aes.h"


//Macros para máscara de bits de encriptación.
#define AES       0x10
#define BLOWFISH  0x20
#define KEY_128   0x01
#define KEY_192   0x02
#define KEY_256   0x04


//Prototipos de funciones.
void print_help(char *exe);
void print_error(char *command);
BYTE mantener_bits_algoritmo(BYTE bitmask);
int equivalente_num_bits(BYTE bitmask);
bool validar_mascara_bits(BYTE bitmask);


//Main.
int main (int argc, char **argv) {
	unsigned long size_archivo_entrada = 0, size_de_cabecera = 0;
	bool kflag = false, dflag = false;
	BLOWFISH_KEY key_schedule_blowfish;
	char nombre_archivo_salida[150] = {0}, *frase_secreta = NULL, *nombre_archivo_entrada = NULL, *algo_consola = NULL;
	SHA256_CTX ctx; //Variable de contexto para hashing.
	BYTE hash_sha256[SHA256_BLOCK_SIZE] = {0}, buffer_entrada[AES_BLOCK_SIZE] = {0}, *hash_trunc = NULL, algorithm_bit = AES;
	int bitsnum = 128, opt, d_archivo_entrada, d_archivo_salida;
	BYTE bitmask = 0, buffer_salida[AES_BLOCK_SIZE] = {0};
	struct stat metadata_archivo;
	WORD key_schedule_aes[60];

	while ((opt = getopt (argc, argv, "a:b:dk:h")) != -1) {
		switch(opt) {
			case 'a':
				algo_consola = optarg;
				if (strcmp(optarg, "aes") == 0)
					algorithm_bit = AES;
				else if (strcmp(optarg, "blowfish") == 0)
					algorithm_bit = BLOWFISH;
				else
					algorithm_bit = 0;
				break;
			case 'b':
				bitsnum = atoi(optarg);
				break;
			case 'd':
				dflag = true;
				break;
			case 'k':
				frase_secreta = optarg;
				kflag = true;
        			break;
			case 'h':
				print_help(argv[0]);
				return 0;
			case '?':
			default:
				print_error(argv[0]);
				return 1;
		}
	}

	//Etapa de validaciones iniciales --------------------------------------------------
	//Validación de ingreso de clave.
	if (!kflag) {
		fprintf(stderr, "Es obligatorio el ingreso de una clave para la encriptación/desencriptación.\n");
		print_error(argv[0]);
		return 1;
	}

	//Validación de cantidad de bits.
	if (bitsnum == 128)
		bitmask = KEY_128;
	else if	(bitsnum == 192)
		bitmask = KEY_192;
	else if (bitsnum == 256)
		bitmask = KEY_256;
	else {
		fprintf(stderr, "Número de bits de encriptación no soportado:\t%d\n", bitsnum);
		fprintf(stderr, "Usar:\t128, 192 ó 256\n");
		print_error(argv[0]);
		return 1;
	}

	//Validación del nombre del archivo.
	for (int index = optind; index < argc; index++)
		nombre_archivo_entrada = argv[index];
	if (!nombre_archivo_entrada) {
		fprintf(stderr, "Es obligatorio el ingreso de un archivo.\n");
		print_error(argv[0]);
		return 1;
	}
	strcpy(nombre_archivo_salida, nombre_archivo_entrada);

	//Validación del algoritmo de encriptación a utilizar.
	if (algorithm_bit == AES)
		bitmask = bitmask | algorithm_bit;
	else if (algorithm_bit == BLOWFISH)
		bitmask = bitmask | algorithm_bit;
	else {
		fprintf(stderr, "Algoritmo de encriptación no soportado:\t%s\n", algo_consola);
		fprintf(stderr, "Algoritmo soportados:\taes, blowfish\n");
		print_error(argv[0]);
		return 1;
	}

	//Obtiene la metadata del archivo original.
	if(stat(nombre_archivo_entrada, &metadata_archivo) < 0){
		fprintf(stderr, "No es posible hallar el archivo:\t%s\n", nombre_archivo_entrada);
		return 1;
	} else {
		size_archivo_entrada = metadata_archivo.st_size;
		d_archivo_entrada = open(nombre_archivo_entrada, O_RDONLY, 0);
	}

	//Parte de hashing. -----------------------------------------------------------------
	sha256_init(&ctx);
	sha256_update(&ctx, (BYTE *)frase_secreta, strlen(frase_secreta));
	sha256_final(&ctx, hash_sha256);
	hash_trunc = (BYTE*)calloc(SHA256_BLOCK_SIZE, sizeof(BYTE));
	memcpy(hash_trunc, hash_sha256, bitsnum/8);

	//Parte de encriptación. -----------------------------------------------------------------
	if (!dflag) {
		size_de_cabecera = __bswap_64(size_archivo_entrada); //Cambia el tamaño del archivo original a little endian.
		strcat(nombre_archivo_salida, ".enc");
		d_archivo_salida = open(nombre_archivo_salida, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
		write(d_archivo_salida, &size_de_cabecera, 8); //Escribe la cabecera en el archivo encriptado.
		write(d_archivo_salida, &bitmask, 1); 		//Escribe la máscara de bits.

		if (algorithm_bit == BLOWFISH) {
			//Blowfish.
			printf("Usando algoritmo blowfish con %d bits de encriptación...\n", bitsnum);
			blowfish_key_setup(hash_trunc, &key_schedule_blowfish, bitsnum);
			while (read(d_archivo_entrada, buffer_entrada, BLOWFISH_BLOCK_SIZE)) {
				blowfish_encrypt(buffer_entrada, buffer_salida, &key_schedule_blowfish);
				write(d_archivo_salida, buffer_salida, BLOWFISH_BLOCK_SIZE);
				memset(buffer_salida, 0, BLOWFISH_BLOCK_SIZE);
				memset(buffer_entrada, 0, BLOWFISH_BLOCK_SIZE);
			}

		} else {
			//aes.
			printf("Usando algoritmo aes con %d bits de encriptación...\n", bitsnum);
			aes_key_setup(hash_trunc, key_schedule_aes, bitsnum);
			while (read(d_archivo_entrada, buffer_entrada, AES_BLOCK_SIZE)) {
				aes_encrypt(buffer_entrada, buffer_salida, key_schedule_aes, bitsnum);
				write(d_archivo_salida, buffer_salida, AES_BLOCK_SIZE);
				memset(buffer_salida, 0, AES_BLOCK_SIZE);
				memset(buffer_entrada, 0, AES_BLOCK_SIZE);
			}
		}
		printf("Archivo '%s' encriptado exitosamente en '%s'.\n", nombre_archivo_entrada, nombre_archivo_salida);

	} else {
	//Parte de desencriptacion. -----------------------------------------------------------------
		int iext = strlen(nombre_archivo_entrada) - 4;
		if (strcmp(nombre_archivo_entrada + iext, ".enc") != 0) {
			fprintf(stderr, "Nombre de archivo no válido:\tarchivo sin extensión .enc\n");
			print_error(argv[0]);
			return 1;
		}
		
		//Leer la metadata del archivo encriptado.
		read(d_archivo_entrada, &size_de_cabecera, 8); //Tamaño del archivo original.
		read(d_archivo_entrada, &bitmask, 1); //Máscara de bits.

		//Verifica si es una máscara de bits válida.
		if (!validar_mascara_bits(bitmask)) {
			fprintf(stderr, "Archivo no válido:\tarchivo con cabecera inválida.\n");
			return 1;
		}

		bitsnum = equivalente_num_bits(bitmask);
		algorithm_bit = mantener_bits_algoritmo(bitmask);
		memset(hash_trunc, 0, SHA256_BLOCK_SIZE);
		memcpy(hash_trunc, hash_sha256, bitsnum/8);
		size_de_cabecera = __bswap_64(size_de_cabecera); //Cambia el tamaño del archivo original a big endian.
		
		memset(nombre_archivo_salida + iext, 0, 4);
		d_archivo_salida = open(nombre_archivo_salida, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	    	long count_readb = 0;

		//aes.
		if (algorithm_bit == AES) {
			printf("Usando algoritmo aes con %d bits de encriptación...\n", bitsnum);
			aes_key_setup(hash_trunc, key_schedule_aes, bitsnum);
			while (read(d_archivo_entrada, buffer_entrada, AES_BLOCK_SIZE)) {
				aes_decrypt(buffer_entrada, buffer_salida, key_schedule_aes, bitsnum);
				count_readb += AES_BLOCK_SIZE;
				if (count_readb > size_de_cabecera)
					write(d_archivo_salida, buffer_salida, size_de_cabecera + AES_BLOCK_SIZE - count_readb);
				else
					write(d_archivo_salida, buffer_salida, AES_BLOCK_SIZE);
				memset(buffer_salida, 0, AES_BLOCK_SIZE);
				memset(buffer_entrada, 0, AES_BLOCK_SIZE);
			}
		} else {
			//Blowfish.
			printf("Usando algoritmo blowfish con %d bits de encriptación...\n", bitsnum);
			blowfish_key_setup(hash_trunc, &key_schedule_blowfish, bitsnum);
			while (read(d_archivo_entrada, buffer_entrada, BLOWFISH_BLOCK_SIZE)) {
				blowfish_decrypt(buffer_entrada, buffer_salida, &key_schedule_blowfish);
				count_readb += BLOWFISH_BLOCK_SIZE;
				if (count_readb > size_de_cabecera)
					write(d_archivo_salida, buffer_salida, size_de_cabecera + BLOWFISH_BLOCK_SIZE - count_readb);
				else
					write(d_archivo_salida, buffer_salida, BLOWFISH_BLOCK_SIZE);
				memset(buffer_salida, 0, BLOWFISH_BLOCK_SIZE);
				memset(buffer_entrada, 0, BLOWFISH_BLOCK_SIZE);
			}
		}	
		printf("Archivo '%s' desencriptado exitosamente en '%s'.\n", nombre_archivo_entrada, nombre_archivo_salida);
	}

	//Todo salió correcto.
	//Cierre de descriptores de archivos.
	//Liberación de memoria dinámica.
	close(d_archivo_entrada);
	free(hash_trunc);
	close(d_archivo_salida);
	return 0;
}


BYTE mantener_bits_algoritmo(BYTE bitmask) {
	bitmask = bitmask & 0x30;
	switch (bitmask) {
		case AES:
			return AES;
		case BLOWFISH:
			return BLOWFISH;
		default:
			return 0;
	}
}


void print_error(char *exe) {
	fprintf(stderr, "%s uso:\n", exe+2);
	fprintf(stderr, "%s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", exe);
	fprintf(stderr, "%s -h\n", exe);
}


int equivalente_num_bits(BYTE bitmask) {
	bitmask = bitmask & 0x07;
	switch (bitmask) {
		case KEY_256:
			return 256;
		case KEY_192:
			return 192;
		case KEY_128:
			return 128;
		default:
			return -1;
	}
}


bool validar_mascara_bits(BYTE bitmask) {
	BYTE bitsnum = bitmask & 0x07;
	BYTE algorithm = bitmask & 0x30;

	if ((bitmask & 0xc8) != 0)
		return false;
	if ((algorithm != BLOWFISH) && (algorithm != AES))
		return false;
	if ((bitsnum != KEY_128) && (bitsnum != KEY_192) && (bitsnum != KEY_256))
		return false;
	return true;
}


void print_help(char *exe) {
	printf("%s encripta o desincripta un archivo usando los algoritmos AES o BLOWFISH.\n", exe+2);
	printf("\nuso:\n");
	printf("%s [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>\n", exe);
	printf("%s -h\n", exe);
	printf("\nOpciones:\n");
	printf("-h\t\t\tAyuda, muestra este mensaje.\n");
	printf("-d\t\t\tDesincripta el archivo en lugar de encriptarlo.\n");
	printf("-k <passphrase>\t\tEspecifica la frase de encriptación.\n");
	printf("-a <algo>\t\tEspecifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]\n");
	printf("-b <bits>\t\tEspecifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]\n");
}


