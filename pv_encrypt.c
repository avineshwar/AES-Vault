#include "pv.h"

void encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  size_t block_size = CCA_STRENGTH;
  int fd;
  if((fd = open(ctxt_fname,O_WRONLY|O_TRUNC|O_CREAT,0600)) < 0)
  {
    perror("Ciphertext file permission error\n");
    exit(EXIT_FAILURE);
  }
  char *iv;
  iv = (char *) malloc(block_size * sizeof(char));
  ri();
  prng_getbytes(iv, block_size);
  struct aes_ctx aes;
  struct aes_ctx mac;
  const char *aes_key = (const char *) raw_sk;
  const char *mac_key = (const char *) raw_sk+CCA_STRENGTH;
  aes_setkey(&aes, aes_key, block_size);
  aes_setkey(&mac, mac_key, block_size); 
  char *buf = buf = (char *) malloc(block_size * sizeof(char)); 
  char *ctxt = ctxt = (char *) malloc(block_size * sizeof(char));
  char *macbuf = (char *) malloc(block_size * sizeof(char));
  char *mac_iv = (char *) malloc(block_size * sizeof(char));
  memset(mac_iv, 0, block_size);
  int result;
  size_t looper = 0;
  size_t bytes_read;
  int iv_increment = 0;
  result = write(fd, iv, block_size);
  if(result == -1)
  {
    exit(-1);
  }
  bytes_read = read(fin, buf, block_size);
  while(bytes_read >= 1)
  {
    *(iv + (block_size - 1)) ^= iv_increment;
    ++iv_increment;
    aes_encrypt(&aes, ctxt, iv);
    for(looper = 0; looper < bytes_read; looper++)
    {
      *(ctxt + looper) = *(ctxt + looper) ^ *(buf + looper);
    }
    for(looper = 0; looper < bytes_read; looper++)
    {
      *(macbuf + looper) = *(ctxt + looper);
    }
    if(bytes_read < 16)
    {
      for(; looper < block_size; looper++)
      {
        *(macbuf + looper) = 0;
      }
      for(looper = 0; looper < block_size; looper++)
      {
        *(macbuf + looper) = *(macbuf + looper) ^ *(mac_iv + looper);
      }
      aes_encrypt(&aes, mac_iv, macbuf);
    }
    else
    {
      for(looper = 0; looper < block_size; looper++)
      {
        *(macbuf + looper) = *(macbuf + looper) ^ *(mac_iv + looper);
      }
      aes_encrypt(&aes, mac_iv, macbuf);
    }
    if(bytes_read < 16)
    {
      result = write_chunk(fd, ctxt, bytes_read);
      if(result == -1)
      {
        perror("Problem when writing to ctxt file... \n");
        close(fd);
        unlink(ctxt_fname); /*for file deletion*/
        aes_clrkey(&aes);
        free(ctxt);
        free(iv);
        free(buf);
        exit(EXIT_FAILURE);
      }
      aes_encrypt(&mac, mac_iv, mac_iv);
      result = write_chunk(fd, mac_iv, block_size);
      if(result == -1)
      {
        perror("Problem when writing to ctxt file... \n");
        close(fd);
        unlink(ctxt_fname); /*for file deletion*/
        aes_clrkey(&aes);
        free(ctxt);
        free(iv);
        free(buf);
        exit(EXIT_FAILURE);
      }
      break;
    }
    else
    {
      result = write_chunk(fd, ctxt, bytes_read);
      if(result == -1)
      {
        perror("Problem when writing to ctxt file... \n");
        close(fd);
        unlink(ctxt_fname); /*for file deletion*/
        aes_clrkey(&aes);
        free(ctxt);
        free(iv);
        free(buf);
        exit(EXIT_FAILURE);
      }
    }
    if((bytes_read = read(fin, buf, block_size)) < 1)
    {
      aes_encrypt(&mac, mac_iv, mac_iv);/*second level MAC. different key used.*/
      result = write_chunk(fd, mac_iv, block_size);
      close(fd);
      aes_clrkey(&aes);
      free(ctxt);
      free(iv);
      free(buf);
      break;
    }
  }
}

void usage (const char *pname)
{
  printf ("Personal Vault: Encryption \n");
  printf ("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
  printf ("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
  printf ("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
  printf ("       If CTEXT-FILE existed, any previous content is lost.\n");

  exit (1);
}

int main (int argc, char **argv)
{
  int fdsk, fdptxt;
  char *raw_sk;
  size_t raw_len;



  if (argc != 4)
  {
      usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1) || ((fdptxt = open (argv[2], O_RDONLY)) == -1))   /*checks for PTXT's readability. checks for SK's readability.*/
  {
      if (errno == ENOENT)
      {
          usage (argv[0]);
      }
      else
      {
          perror (argv[0]);

          exit (-1);
      }
  }
  else
  {
      setprogname (argv[0]);

      /* Import symmetric key from argv[1] */
      if (!(import_sk_from_file (&raw_sk, &raw_len, fdsk)))   /*Checks for SK's existence.*/
      {
          printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);

          close (fdsk);
          exit (2);
      }
      close (fdsk);

      /* Enough setting up---let's get to the crypto... */
      encrypt_file (argv[3], raw_sk, raw_len, fdptxt);

      /* scrub the buffer that's holding the key before exiting */

              bzero(raw_sk, raw_len);
              free(raw_sk);


      close (fdptxt);
  }

  return 0;
}
