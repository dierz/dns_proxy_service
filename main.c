#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/stat.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define PORT 53 
#define MAXLINE 1024 
#define NAME_INDEX 13
#define DNS_SIZE_WO_NAME 18
#define CHAR_DOT 0x2e
#define MAIN_SECT "[main]"
#define BL_SECT "[blacklist]"
#define ALT_DNS "alt_dns"
#define BANNED "banned"
#define NOTRSL "not_resolved"
#define LCLIP "local_ip"
#define CONFIG_FIlE "/etc/proxy-dns"
#define PID_FILE "/var/run/main.pid"

void get_parameters(char * line);
void get_domain_name(char * buf, int len, char * out);
void prepare_response(char * buf, int len, char * out, unsigned long adr);
int is_blacklisted(char * name);
//IP address of the superior DNS server.
char * alt_dns;
// Option that determines which way system handles blacklisted domain
int banned;
// List of blacklisted domains
char * blacklist[100];

int main() {
  FILE * fp;
  int sockfd;
  char buffer[MAXLINE];
  char response[MAXLINE];
  char name[100];
  struct sockaddr_in servaddr, cliaddr;
  int config_mode = 0;
  char str[100];
  int ptr = 0;
  pid_t process_id = 0;
  pid_t sid = 0;

  //deamonizing
  process_id = fork();

  if (process_id < 0) {
    printf("Fork failed!\n");
    exit(1);
  }

  if (process_id > 0) {
    fp = fopen(PID_FILE, "w");
    if (fp == NULL) {
      perror("Error opening file");
      exit(1);
    }
    fprintf(fp, "%d", process_id);
    fclose(fp);
    exit(0);
  }
  umask(0);
  sid = setsid();

  if (sid < 0) {
    exit(1);
  }
  chdir("/");
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  fp = fopen(CONFIG_FIlE, "r");
  if (fp == NULL) {
    perror("Error opening file");
    return (-1);
  }

  while (fgets(str, 100, fp) != NULL) {
    str[strlen(str) - 1] = 0;

    if (str[0] == '/' || str[0] == 0) {
      memset(str, 0, sizeof(str));
      continue;
    }

    switch (config_mode) {
    case 0:
      {
        if (strcmp(MAIN_SECT, str) != 0) {
          get_parameters(str);
        }
        if (strcmp(BL_SECT, str) == 0) {
          config_mode = 1;
        }
      }
      break;
    case 1:
      {
        if (strcmp(MAIN_SECT, str) == 0) {
          config_mode = 0;
          break;
        }
        if (ptr == 100)
          break;

        blacklist[ptr] = malloc(strlen(str) + 1);
        strcpy(blacklist[ptr], str);
        ptr++;
      }
      break;
    }
    memset(str, 0, sizeof(str));
  }
  fclose(fp);

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset( & servaddr, 0, sizeof(servaddr));
  memset( & cliaddr, 0, sizeof(cliaddr));
  memset( & name, 0, sizeof(name));

  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(PORT);

  if (bind(sockfd, (const struct sockaddr * ) & servaddr, sizeof(servaddr)) < 0) {
    perror("Bind failed");
    exit(EXIT_FAILURE);
  }

  int len, n;
  do {
    n = recvfrom(sockfd, (char * ) buffer, MAXLINE, MSG_WAITALL, (struct sockaddr * ) & cliaddr, & len);
    buffer[n] = 0;
	//NAME_INDEX - index of byte sequence where domain name starts
    get_domain_name( & buffer[NAME_INDEX], n - DNS_SIZE_WO_NAME, name);
    switch (is_blacklisted(name)) {
    case 0:
      {
        unsigned long host = cliaddr.sin_addr.s_addr;
        unsigned short host_port = cliaddr.sin_port;
        inet_aton(alt_dns, & cliaddr.sin_addr.s_addr);
        cliaddr.sin_port = htons(PORT);
        sendto(sockfd, (const char * ) buffer, n, MSG_CONFIRM, (const struct sockaddr * ) & cliaddr, len);
        memset( & buffer, 0, sizeof(buffer));
        n = recvfrom(sockfd, (char * ) buffer, MAXLINE, MSG_WAITALL, (struct sockaddr * ) & cliaddr, & len);
        cliaddr.sin_addr.s_addr = host;
        cliaddr.sin_port = host_port;
        sendto(sockfd, (const char * ) buffer, n, MSG_CONFIRM, (const struct sockaddr * ) & cliaddr, len);
      }
      break;
    case 1:
      {
        memset( & response, 0, n + 16);
        for (int i = 0; i < n; i++) {
          response[i] = buffer[i];
        }
        prepare_response(buffer, n, response, cliaddr.sin_addr.s_addr);
		//16 - additional size of response
        sendto(sockfd, (const char * ) response, n + 16, MSG_CONFIRM, (const struct sockaddr * ) & cliaddr, len);
      }
      break;
    }
    memset( & name, 0, sizeof(name));
    memset( & buffer, 0, sizeof(buffer));
    memset( & response, 0, sizeof(response));
  }
  while (n >= 0);
  close(sockfd);
  free(blacklist);
  free(alt_dns);
  return 0;
}
// Retrieving domain name from received DNS packet
void get_domain_name(char * buf, int len, char * out) {

  for (int i = 0; i < len; i++) {
	  // There are only control codes less than 0x20
    if ( * buf < 0x20) {
      out[i] = CHAR_DOT;
    } else {
      out[i] = * buf;
    }
    buf++;
  }
}
// Parsing parameters under section 'main' to the system
void get_parameters(char * line) {
  const char * s = "=";
  char * token;

  token = strtok(line, s);
  if (!strcmp(token, ALT_DNS)) {
    token = strtok(NULL, s);
    alt_dns = malloc(strlen(token) + 1);
    strcpy(alt_dns, token);
  } else if (!strcmp(token, BANNED)) {
    token = strtok(NULL, s);
    if (!strcmp(token, NOTRSL)) {
      banned = 1;
    } else if (!strcmp(token, LCLIP)) {
      banned = 0;
    }
  }
}
// Checks whether given domain in blacklist or not
int is_blacklisted(char * name) {
  int i = 0;
  while (blacklist[i] != NULL) {
    if (!strcmp(blacklist[i], name)) {
      return 1;
    }
    i++;
  }
  return 0;
}

//Forms response payload in the case of domain occured in blacklist
void prepare_response(char * buf, int len, char * out, unsigned long adr) {

  switch (banned) {
// Configuring DNS packet to return local ip as response
  case 0:
    {
      out[2] = 0x81;
      out[3] = 0x80;
      out[7] = 0x01;
      out[len] = 0xc0;
      out[len + 1] = 0x0c;
      out[len + 3] = 0x01;
      out[len + 5] = 0x01;
      out[len + 9] = 0xFF;
      out[len + 11] = 0x04;
      out[len + 15] = (adr - (adr % 0x1000000)) / 0x1000000;
      adr = adr - out[len + 15] * 0x1000000;
      out[len + 14] = (adr - (adr % 0x10000)) / 0x10000;
      adr = adr - out[len + 14] * 0x10000;
      out[len + 13] = (adr - (adr % 0x100)) / 0x100;
      adr = adr - out[len + 13] * 0x100;
      out[len + 12] = adr;
    }
    break;
// Configuring DNS packet to access refuse
  case 1:
    {
      out[2] = 0x81;
      out[3] = 0x85;
    }
    break;
  }
}