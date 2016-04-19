#include "pv.h"

void decrypt_file (const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin, int fin1, int fin2)
{
  int fd;
  size_t file_size, ciphertext_file_size = 0;
  if((fd = open(ptxt_fname, O_RDWR | O_CREAT | O_EXCL, 0600)) < 0)
  {    
    perror("plaintext file permission error\n");
    exit(EXIT_FAILURE);
  }
  size_t block_size = CCA_STRENGTH;
  const char *mac_key;
  const char *aes_key;
  aes_key = (const char *) raw_sk;
  mac_key = (const char *) raw_sk+CCA_STRENGTH;
  aes_ctx aes;
  aes_ctx mac;
  aes_setkey(&aes, aes_key, block_size);
  aes_setkey(&mac, mac_key, block_size);
  char *mac_iv = (char *) malloc(block_size * sizeof(char));
  memset(mac_iv, 0, block_size);
  char *buf = (char *) malloc(block_size * sizeof(char));
  size_t loop_variable = 0;
  char *iv;
  iv = (char *) malloc(block_size * sizeof(char));
  char *test = (char *) malloc(33);
  size_t bytes_read;
  while ((bytes_read = read(fin1, test, (2 * block_size) + 1)) >= 1)
  {
    ciphertext_file_size = ciphertext_file_size + bytes_read;
  }
  bzero(test, 33);
  free(test);
  close(fin1);
  bytes_read = read(fin2, iv, block_size);
  ciphertext_file_size = ciphertext_file_size - (2 * bytes_read);
  file_size = ciphertext_file_size;
  while(ciphertext_file_size > 0)
  {
    if((ciphertext_file_size/16) >=1)
    {
      ciphertext_file_size = ciphertext_file_size - block_size;
      bytes_read = read(fin2, buf, block_size);
      if(ciphertext_file_size == 0)
      {
        for(loop_variable = 0; loop_variable < block_size; loop_variable++)
        {
          *(buf + loop_variable) = *(buf + loop_variable) ^ *(mac_iv + loop_variable);
        }
        aes_encrypt(&aes, mac_iv, buf);
        aes_encrypt(&mac, mac_iv, mac_iv);
        break;
      }
      else
      {
        for(loop_variable = 0; loop_variable < block_size; loop_variable++)
        {
          *(buf + loop_variable) = *(buf + loop_variable) ^ *(mac_iv + loop_variable);
        }
        aes_encrypt(&aes, mac_iv, buf);
      }
    }
    else
    {               
      bytes_read = read(fin2, buf, ciphertext_file_size);
      ciphertext_file_size = ciphertext_file_size - bytes_read;
      for(; bytes_read < block_size; bytes_read++)
      {
        *(buf + bytes_read) = 0;
      }
      for(loop_variable = 0; loop_variable < block_size; loop_variable++)
      {
        *(buf + loop_variable) = *(buf + loop_variable) ^ *(mac_iv + loop_variable);
      }
      aes_encrypt(&aes, mac_iv, buf);
      aes_encrypt(&mac, mac_iv, mac_iv);
    }
  }
  bytes_read = read(fin2, buf, block_size);
  loop_variable = 0;
  for(; loop_variable < block_size; loop_variable++)
  {
    if(*(mac_iv + loop_variable) != *(buf + loop_variable))
    {
      printf("MAC failed.\n\n");
      exit(-1);
    }
  }
  printf("MAC passed. Data integrity is maintained. Moving with the decryption now.\n\n");
  close(fin2);
  char *ptxt = (char *) malloc(block_size * sizeof(char)); /*p-text buffer*/
  int result, counter = 0;
  loop_variable = 0;
  bytes_read = read(fin, iv, block_size);
  if(bytes_read != 16)
  {
    exit(-1);
  }
  bytes_read = 0;
  if(((file_size % 16 == 0) || ((file_size / 16) >= 1)) && (file_size > 0))
  {
    bytes_read = read(fin, buf, block_size);
    file_size = file_size - bytes_read;
  }
  else
  {
    if( file_size >= 1)
    {
      bytes_read = read(fin, buf, file_size);
      file_size = file_size - bytes_read;
    }
  }
  while(bytes_read >= 1)
  {
    *(iv + (block_size - 1)) ^= counter;
    ++counter;
    aes_encrypt(&aes, ptxt, iv);
    for(loop_variable = 0; loop_variable < bytes_read; loop_variable++)
    {
      *(ptxt + loop_variable) = *(ptxt + loop_variable) ^ *(buf + loop_variable);
    }
    if((result = write_chunk(fd, ptxt, bytes_read)) == -1)
    {
      perror("Problem when writing to ptxt file... \n");
      close(fd);
      unlink(ptxt_fname); /*for file deletion*/
      aes_clrkey(&aes);
      free(ptxt);
      free(iv);
      free(buf);
      exit(EXIT_FAILURE);
    }
    if(((file_size % 16 == 0) || ((file_size / 16) >= 1)) && (file_size > 0))
    {
      bytes_read = read(fin, buf, block_size);  
      file_size = file_size - bytes_read;
    }
    else if(file_size > 0)
    {
      bytes_read = read(fin, buf, file_size);
      file_size = file_size - bytes_read;
    }
    else
    {
      close(fd);
      aes_clrkey(&aes);
      free(ptxt);
      free(iv);
      free(buf);
      break;
    }
  }
}

void
usage (const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n");
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int main (int argc, char **argv)
{
  int fdsk, fdctxt, fdctxt1, fdctxt2;
  char *sk = NULL;
  size_t sk_len = 0;

  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1) || ((fdctxt = open (argv[2], O_RDONLY)) == -1) || ((fdctxt1 = open (argv[2], O_RDONLY)) == -1) || ((fdctxt2 = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);

      exit (-1);
    }
  }
  else {
    setprogname (argv[0]);

    /* Import symmetric key from argv[1] */
    if (!(sk = import_sk_from_file (&sk, &sk_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);

      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
        /* Actually, this should be "let's go decrypto..."*/
    decrypt_file (argv[3], sk, sk_len, fdctxt, fdctxt1, fdctxt2);
        /*arguments are "decrypted-file, pointer to sk buffer, 0, 0"*/

        bzero(sk, sk_len);
        free(sk);


    close (fdctxt);
  }

  return 0;
}
