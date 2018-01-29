#include <ctype.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "sa_snort.h"
#include "onvm_mgr.h"
#include "onvm_pkt.h"
#include "onvm_nf.h"
#include "onvm_init.h"
#include "onvm_pkt_helper.h"
#include "onvm_common.h"
#include "fastpath_pkt.h"
/****************************FP Snort Variables****************************/
extern int file_line;      /* current line being processed in the rules file */
extern int rule_count;
extern Rule *current;      /* util ptr for the current rule */
extern Rule *PassList;     /* List of Pass Rules */
extern Rule *LogList;      /* List of Log Rules */
extern Rule *AlertList;    /* List of Alert Rules */
extern PrintIP pip;

/****************************************************************************
 *
 * Function: strip(char *)
 *
 * Purpose: Strips a data buffer of CR/LF/TABs.  Replaces CR/LF's with
 *          NULL and TABs with spaces.
 *
 * Arguments: data => ptr to the data buf to be stripped
 *
 * Returns: size of the newly stripped string
 *
 ****************************************************************************/
int strip(char *data)
{
   int size;
   char *end;
   char *idx;

   idx = data;
   end = data + strlen(data);
   size = end - idx;

   while(idx != end)
   {
      if((*idx == '\n') ||
         (*idx == '\r'))
      {
         *idx = 0;
         size--;
      }

      if(*idx == '\t')
      {
         *idx = ' ';
      }

      idx++;
   }

   return size;
}

/****************************************************************
 *  
 *  Function: mSplit()
 * 
 *  Purpose: Splits a string into tokens non-destructively.
 *
 *  Parameters: 
 *      char *str => the string to be split
 *      char *sep => a string of token seperaters
 *      int max_strs => how many tokens should be returned
 *      int *toks => place to store the number of tokens found in str
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/

char **mSplit(char *str, char *sep, int max_strs, int *toks, char meta)
{
   char **retstr;    /* 2D array which is returned to caller */
   char *idx;        /* index pointer into str */
   char *end;        /* ptr to end of str */
   char *sep_end;    /* ptr to end of seperator string */
   char *sep_idx;    /* index ptr into seperator string */
   int len = 0;      /* length of current token string */
   int curr_str = 0; /* current index into the 2D return array */
   char last_char = 0xFF;

#ifdef DEBUG2
   printf("[*] Splitting string: %s\n", str);
   printf("curr_str = %d\n", curr_str);
#endif
   
   /* find the ends of the respective passed strings so our while() 
      loops know where to stop */
   sep_end = sep + strlen(sep);
   end = str + strlen(str);

   /* set our indexing pointers */
   sep_idx = sep;
   idx = str;

   /* alloc space for the return string, this is where the pointers to the
      tokens will be stored */
   retstr = (char **) malloc((sizeof(char **) * max_strs));

   /* loop thru each letter in the string being tokenized */
   while(idx < end)
   {
      /* loop thru each seperator string char */
      while(sep_idx < sep_end)
      {
         /* if the current string-indexed char matches the current
            seperator char... */
         if((*idx == *sep_idx)&&
            (last_char != meta))
         {
            /* if there's something to store... */
            if(len > 0)
            {
#ifdef DEBUG2
               printf("Allocating %d bytes for token ", len + 1);
               fflush(stdout);
#endif
               if(curr_str < max_strs)
               {
                  /* allocate space for the new token */
                  retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1);

                  /* make sure we got a good allocation */
                  if(retstr[curr_str] == NULL)  
                  {
                     fprintf(stderr, "msplit() got NULL substring malloc!\n");
                     exit(1);
                  }

                  /* copy the token into the return string array */
                  memcpy(retstr[curr_str], (idx - len), len);
                  retstr[curr_str][len] = 0; 
#ifdef DEBUG2
                  printf("%s\n", retstr[curr_str]);
                  fflush(stdout);
#endif
                  /* twiddle the necessary pointers and vars */
                  len = 0;
                  curr_str++;
#ifdef DEBUG2
                  printf("curr_str = %d\n", curr_str);
#endif
		  last_char = *idx;
                  idx++;
               }

               /* if we've gotten all the tokens requested, return the list */
               if(curr_str >= max_strs)
               {
                  *toks = curr_str + 1;
#ifdef DEBUG2
                  printf("mSplit got %d tokens!\n", *toks);
                  fflush(stdout);
#endif
                  return retstr;
               }
            }
            else  /* otherwise, the previous char was a seperator as well,
                     and we should just continue */
            {
               last_char = *idx;
               idx++;
               /* make sure to reset this so we test all the sep. chars */
               sep_idx = sep;
               len = 0;
            }
         }
         else
         {
            /* go to the next seperator */
            sep_idx++;
         }
      }

      sep_idx = sep;
      len++;
      last_char = *idx;
      idx++;
   }

   /* put the last string into the list */

   if(len > 0)
   {
#ifdef DEBUG2
      printf("Allocating %d bytes for token ", len + 1);
      fflush(stdout);
#endif

      retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1);

      if(retstr[curr_str] == NULL)
         printf("Got NULL back from substr malloc\n");

      memcpy(retstr[curr_str], (idx - len), len);
      retstr[curr_str][len] = 0; 

#ifdef DEBUG2
      printf("%s\n", retstr[curr_str]);
      fflush(stdout);
#endif
      *toks = curr_str + 1;
   }

#ifdef DEBUG2
   printf("mSplit got %d tokens!\n", *toks);
   fflush(stdout);
#endif   

   /* return the token list */
   return retstr;
}

/****************************************************************************
 *       
 * Function: ConvPort(char *, char *)
 *    
 * Purpose:  Convert the port string over to an integer value
 * 
 * Arguments: port => port string
 *            proto => converted integer value of the port
 *
 * Returns:  the port number
 *
 ***************************************************************************/

int ConvPort(char *port, char *proto)
{
   int conv;  /* storage for the converted number */
   struct servent *service_info;

   /* convert a "word port" (http, ftp, imap, whatever) to its
      corresponding numeric port value */
   if(isalpha(port[0]) != 0)
   {
      service_info = getservbyname(port, proto);
 
      if(service_info != NULL)
      {
         conv = ntohs(service_info->s_port);
         return conv; 
      }
      else
      {
         fprintf(stderr, "ERROR Line %d => getservbyname() failed on \"%s\"\n",
                 file_line, port);
         exit(1);
      }
   }

   if(!isdigit(port[0]))
   {
      fprintf(stderr, "ERROR Line %d => Invalid port: %s\n", file_line, port);
      exit(1);
   }  
   
   /* convert the value */
   conv = atoi(port);
   
   /* make sure it's in bounds */
   if((conv >= 0) && (conv < 65536))
   {
      return conv;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d => bad port number: %s", file_line, port);
      exit(1);
   }
}

/****************************************************************************
 *
 * Function: RuleType(char *)
 *
 * Purpose:  Determine what type of rule is being processed and return its
 *           equivalent value
 *
 * Arguments: func => string containing the rule type
 *
 * Returns: The rule type designation
 *
 ***************************************************************************/

 int RuleType(char *func)
{
   if(!strncasecmp(func, "log",3))
      return RULE_LOG;

   if(!strncasecmp(func, "alert",5))
      return RULE_ALERT;

   if(!strncasecmp(func, "pass",4))
      return RULE_PASS;

   
   printf("ERROR line %d => Unknown Rule action: %s\n", file_line, func);
   // CleanExit();
  
   return 0;
}

/****************************************************************************
 *
 * Function: CreateRuleNode(int)
 *
 * Purpose:  Allocate space for a rule and attach it to the end of the
 *           program rule list
 *
 * Arguments: type => the current rule type (pass/alert/log)
 *
 * Returns: void function
 *
 ***************************************************************************/

void CreateRuleNode(int type)
{
   Rule *idx;  /* index ptr for walking the rules list */

   idx = PassList;

   /* alloc a new rule */
   current = (Rule *) malloc(sizeof(Rule));

   if(current == NULL)
   {
      perror("CreateRuleNode()");
      exit(1);
   }

   /* clear the next ptr */
   current->next = NULL;
  
   /* figure out which list the current rule should be added to */
   switch(type)
   {
      case RULE_LOG: if(LogList == NULL)
                     {
                        LogList = current;
                        return;
                     }
                     else
                     {
                        idx = LogList;
                     }

                     break;

      case RULE_PASS: if(PassList == NULL)
                      {
                         PassList = current;
                         return;
                      }
                      else
                      {
                         idx = PassList;
                      }

                      break;

      case RULE_ALERT: if(AlertList == NULL)
                       {
                          AlertList = current;
                          return;
                       }
                       else
                       {
                          idx = AlertList;
                       }
                       break;
   }

   /* loop thru the list and add the current rule to the end */
   while(idx->next != NULL)
   {
      idx = idx->next;
   }

   idx->next = current;

   return;
}

/****************************************************************************
 *
 * Function: WhichProto(char *)
 *
 * Purpose: Figure out which protocol the current rule is talking about
 *
 * Arguments: proto_str => the protocol string
 *
 * Returns: The integer value of the protocol
 *
 ***************************************************************************/

int WhichProto(char *proto_str)
{
   if(!strncasecmp(proto_str, "tcp", 3))
      return IPPROTO_TCP;

   if(!strncasecmp(proto_str, "udp", 3))
      return IPPROTO_UDP;

   if(!strncasecmp(proto_str, "icmp", 4))
      return IPPROTO_ICMP;

   fprintf(stderr, "ERROR Line %d => Bad protocol: %s\n", file_line, proto_str);
   exit(1);
}
/****************************************************************************
 *
 * Function: ParseIP(char *, u_long *, u_long *)
 *
 * Purpose: Convert a supplied IP address to it's network order 32-bit long
 *          value.  Also convert the CIDER block notation into a real 
 *          netmask. 
 *
 * Arguments: addr => address string to convert
 *            ip_addr => storage point for the converted ip address
 *            netmask => storage point for the converted netmask
 *
 * Returns: 0 for normal addresses, 1 for an "any" address
 *
 ***************************************************************************/

int ParseIP(char *addr, u_long *ip_addr, u_long *netmask)
{
   char **toks;                /* token dbl buffer */
   int num_toks;               /* number of tokens found by mSplit() */
   int nmask;                  /* netmask temporary storage */
   struct hostent *host_info;  /* various struct pointers for stuff */
   struct sockaddr_in sin;     /* addr struct */

   /* check for wildcards */
   if(!strncasecmp(addr, "any", 3))
   {
      *ip_addr = 0;
      *netmask = 0;
      return 1;
   }
 
   /* break out the CIDER notation from the IP address */
   char stringg[] = "/";
   toks = mSplit(addr,stringg,2,&num_toks,0);

   if(num_toks != 2)
   {
      fprintf(stderr, "ERROR Line %d => No netmask specified for IP address %s\n", file_line, addr);
      exit(1);
   }

   /* convert the CIDER notation into a real live netmask */
   nmask = 32 - atoi(toks[1]);

   *netmask = pow(2, nmask) - 1;
   *netmask = -(*netmask);
   *netmask -= 1;

#ifndef WORDS_BIGENDIAN
   /* since PC's store things the "wrong" way, shuffle the bytes into
      the right order */
   *netmask = htonl(*netmask);
#endif

   /* convert names to IP addrs */
   if(isalpha(toks[0][0]))
   {
      /* get the hostname and fill in the host_info struct */
      if((host_info = gethostbyname(toks[0])))
      {
         bcopy(host_info->h_addr, (char *)&sin.sin_addr, host_info->h_length);
      }
      else if((sin.sin_addr.s_addr = inet_addr(toks[0])) == INADDR_NONE)
      {
         fprintf(stderr,"ERROR Line %d => Couldn't resolve hostname %s\n", 
                 file_line, toks[0]);
         exit(1);
      }

      *ip_addr = ((u_long)(sin.sin_addr.s_addr) & (*netmask));
      return 1;
   }

   /* convert the IP addr into its 32-bit value */
   if((signed)(*ip_addr = inet_addr(toks[0])) == -1)
   {
      fprintf(stderr, "ERROR Line %d => Rule IP addr (%s) didn't x-late, WTF?\n",
              file_line, toks[0]);
      exit(0);
   }
   else
   {
      /* set the final homenet address up */
      *ip_addr = ((u_long)(*ip_addr) & (*netmask));
   }

   free(toks);

   return 0;
}



/****************************************************************************
 *
 * Function: ParsePort(char *, u_short *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: rule_port => port string
 *            port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/

int ParsePort(char *rule_port, u_short *hi_port, u_short *lo_port, char *proto, int *not_flag)
{
   char **toks;                /* token dbl buffer */
   int num_toks;               /* number of tokens found by mSplit() */

   *not_flag = 0;

   /* check for wildcards */
   if(!strncasecmp(rule_port, "any", 3))
   {
      *hi_port = 0;
      *lo_port = 0;
      return 1;
   }

   if(rule_port[0] == '!')
   {
      *not_flag = 1;
      rule_port++;
   }

   if(rule_port[0] == ':')
   {
      *lo_port = 0;
   }

   char stringggg[] = ":";
   toks = mSplit(rule_port, stringggg, 2, &num_toks,0);

   switch(num_toks)
   {
      case 1:
              *hi_port = ConvPort(toks[0], proto);

              if(rule_port[0] == ':')
              {
                 *lo_port = 0;
              }
              else
              {
                 *lo_port = *hi_port;

                 if(index(rule_port, ':') != NULL)
                 {
                    *hi_port = 65535;
                 }
              }

              return 0;

      case 2:
              *lo_port = ConvPort(toks[0], proto);

              if(toks[1][0] == 0)
                 *hi_port = 65535;
              else
                 *hi_port = ConvPort(toks[1], proto);

              return 0;

      default:
               fprintf(stderr, "ERROR Line %d => port conversion failed on \"%s\"\n",
                       file_line, rule_port);
               exit(1);
   }             

   return 0;
}

void ParseRuleOptions(char *rule)
{
   char **toks = NULL;
   int num_toks;
   char *idx;
   char *aux;
   int i;
   char **opts;
   int num_opts;

   idx = index(rule, '(');
   i = 0;

   if(idx != NULL)
   {
      idx++;
      aux = index(idx,')');
      *aux = 0;

#ifdef DEBUG
      printf("[*] Rule: %s\n", idx);
#endif

      /* seperate all the options out */
	  char stringccc[] = ";";
      toks = mSplit(idx, stringccc, 10, &num_toks,'\\');

#ifdef DEBUG
      printf("   Got %d tokens\n", num_toks);
#endif

      num_toks--;
      while(num_toks)
      {
#ifdef DEBUG
         printf("   option: %s\n", toks[i]);
#endif
		
		char stringbbb[] = ":";
         opts = mSplit(toks[i], stringbbb, 4, &num_opts,'\\');
         
#ifdef DEBUG
         printf("   option name: %s\n", opts[0]);
         printf("   option args: %s\n", opts[1]);
#endif

         while(isspace(*opts[0])) opts[0]++;
	 if(!strcasecmp(opts[0], "content"))
         {
	    ParsePattern(opts[1]);
	 }
         else if(!strcasecmp(opts[0], "msg"))
	      {
		 ParseMessage(opts[1]);
	      }
	      else if(!strcasecmp(opts[0], "flags"))
	           {
		      ParseFlags(opts[1]);
		   }
	           else if(!strcasecmp(opts[0], "ttl"))
		        {
		           aux = opts[1];
	                   while(isspace(*aux)) aux++;
			   current->ttl = atoi(opts[1]);
#ifdef DEBUG
			   printf("Set TTL to %d\n", current->ttl);
#endif
			}
		        else if(!strcasecmp(opts[0], "itype"))
			     {
				ParseItype(opts[1]);
			     }
		             else if(!strcasecmp(opts[0], "icode"))
			          {
				     ParseIcode(opts[1]);
			          }
         free(opts);
	 --num_toks;
	 i++;
      }
   }

   free(toks);
}

/****************************************************************************
 *
 * Function: ParseRulesFile(char *)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *           the rule parser
 *
 * Arguments: file => rules file filename
 *
 * Returns: void function
 *
 ***************************************************************************/

 void ParseRulesFile(char *file)
{
   FILE *thefp;       /* file pointer for the rules file */
   char buf[STD_BUF]; /* file read buffer */

#ifdef DEBUG
   printf("Opening rules file: %s\n", file);
#endif

   /* open the rules file */
   if((thefp = fopen(file,"r")) == NULL)
   {
      printf("Unable to open rules file: %s\n", file);
      exit(1);
   }

   /* clear the line buffer */
   bzero(buf, STD_BUF);

   /* loop thru each file line and send it to the rule parser */
   while((fgets(buf, STD_BUF, thefp)) != NULL)
   {
      /* inc the line counter so the error messages know which line to 
         bitch about */
      file_line++;

#ifdef DEBUG2
      printf("Got line %d: %s", file_line, buf);
#endif
      /* if it's not a comment or a <CR>, send it to the parser */
      if((buf[0] != '#') && (buf[0] != 0x0a) && (buf[0] != ';'))
      {
         ParseRule(buf);
      }

      bzero(buf, STD_BUF);
   }

   printf("System configured with %d rules.\n",rule_count);

// #ifdef DEBUG
   // DumpRuleList(AlertList);
   // DumpRuleList(PassList);
   // DumpRuleList(LogList);
// #endif

   fclose(thefp);

   return;
}


/****************************************************************************
 *
 * Function: ParseRule(char *)
 *
 * Purpose:  Process an individual rule and add it to the rule list
 *
 * Arguments: rule => rule string
 *
 * Returns: void function
 *
 ***************************************************************************/

void ParseRule(char *rule)
{
   char **toks;          /* dbl ptr for mSplit call, holds rule tokens */
   int num_toks;         /* holds number of tokens found by mSplit */
   int rule_type;        /* rule type enumeration variable */


   /* chop off the <CR/LF> from the string */
   strip(rule);

   /* break out the tokens from the rule string */
   char stringaaa[] = " ";
   toks = mSplit(rule, stringaaa, 10, &num_toks,0);

   rule_type = RuleType(toks[0]);

   /* Make a rule node */
   CreateRuleNode(rule_type);
   rule_count++;
   current->rule_num = rule_count;
                       
   /* figure out what type (pass/log/alert) rule is being looked at */
   current->type = rule_type;
 
   /* set the rule protocol */
   current->proto = WhichProto(toks[1]);

   /* Process the IP address and CIDER netmask */
   /* if this is an "any" addr, set the flag */
   if(ParseIP(toks[2], (u_long *) &current->sip, (u_long *) &current->smask))
      current->flags |= ANY_SRC_IP;

   /* do the same for the port */
   if(ParsePort(toks[3], (u_short *) &current->hsp, (u_short *) &current->lsp, toks[1], 
               (int *) &current->not_sp_flag))
      current->flags |= ANY_SRC_PORT;

   if(ParseIP(toks[5], (u_long *) &current->dip, (u_long *) &current->dmask))
      current->flags |= ANY_DST_IP;

   if(ParsePort(toks[6], (u_short *) &current->hdp, (u_short *) &current->ldp, toks[1], 
                (int *) &current->not_sp_flag))
      current->flags |= ANY_DST_PORT;

   /* decode the rest of the rule content */

   ParseRuleOptions(rule);

   free(toks);

   return;
}

/****************************************************************************
 *
 * Function: ParsePattern(char *)
 *
 * Purpose: Process the application layer patterns and attach them to the
 *          appropriate rule.  My god this is ugly code.
 *
 * Arguments: rule => the rule string 
 *
 * Returns: void function
 *
 ***************************************************************************/

void ParsePattern(char *rule)
{
   /* got enough ptrs for you? */
   char *start_ptr;
   char *end_ptr;
   char *idx;
   char *dummy_buf;
   char *dummy_idx;
   char *dummy_end;
   char hex_buf[9];
   u_int dummy_size = 0;
   unsigned int size;
   int hexmode = 0;
   int hexsize = 0;
   int pending = 0;
   int cnt = 0;

   start_ptr = index(rule,'"');

   if(start_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   start_ptr++;
   

   end_ptr = index(start_ptr, '"');

   if(end_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   *end_ptr = 0;
   size = end_ptr - start_ptr;
   
   if(size <= 0)
   {
      fprintf(stderr, "ERROR Line %d => Bad pattern length!\n", file_line);
      exit(1);
   }

   dummy_buf = (char *) malloc(sizeof(char)*size);

   if(dummy_buf == NULL)
   {
      fprintf(stderr, "ERROR => ParsePattern() buf malloc failed!\n");
      perror("malloc()");
      exit(1);
   }

   idx = start_ptr;
   dummy_idx = dummy_buf;
   dummy_end = (dummy_idx + size);

   bzero(hex_buf, 9);
   bzero(dummy_buf, size);
   memset(hex_buf, '0', 8);

   while(idx < end_ptr)
   {
      if(!hexmode)
      {
         if(*idx == '|')
         {
            hexmode = 1;
            hexsize = 0;
         }
         else
         {
            if(*idx >= 0x20 && *idx <= 0x7D)
            {
               if(dummy_idx < dummy_end)
               {
                  if(*idx != '\\')
		  {
                     dummy_buf[dummy_size] = start_ptr[cnt];
                     dummy_size++;
		  }
               }
               else
               {
                  fprintf(stderr, "ERROR => ParsePattern() dummy buffer overflow!\n");
                  exit(1);
               }
            }
	    else
	    {
               fprintf(stderr, "ERROR => character value out of range, try a binary buffer dude\n");
	       exit(1);
	    }
         }
      }
      else
      {
         if(*idx == '|')
         {
            hexmode = 0;

            if(!hexsize)
            {
               dummy_buf[dummy_size] = '|';
               dummy_size++;
            }
         }
         else
         {
            if(isxdigit(*idx))
            {
               hexsize++;

               if(!pending)
               {
                  hex_buf[7] = *idx;
                  pending++;
               }
               else
               {
                  hex_buf[8] = *idx;
                  pending--;

                  if(dummy_idx < dummy_end)
                  {
                     dummy_buf[dummy_size] = (u_long) strtol(hex_buf, (char **)NULL, 16);

                     dummy_size++;
                     bzero(hex_buf, 9);
                     memset(hex_buf, '0', 8);
                  }
                  else
                  {
                     fprintf(stderr, "ERROR => ParsePattern() dummy buffer overflow!\n");
                     exit(1);
                  }
               }
            }
            else
            {
               if(*idx != ' ')
               {
                  fprintf(stderr, "ERROR Line %d => Serious weirdness in binary buffer!\n", file_line);
                  exit(1);
               }
            }
         }
      }

      dummy_idx++;
      idx++;
      cnt++;
   }

/*   if(*idx >= 0x20 && *idx <= 0x7D)
   {
      if(dummy_idx < dummy_end)
      {
         dummy_buf[dummy_size] = start_ptr[cnt];
         dummy_size++;
      }
   }
*/
   if((current->pattern_buf=(char *)malloc(sizeof(char)*dummy_size))==NULL)
   {
      fprintf(stderr, "ERROR => ParsePattern() pattern_buf malloc filed!\n");
      exit(1);
   }

   memcpy(current->pattern_buf, dummy_buf, dummy_size);

   current->pattern_size = dummy_size;

   bzero(dummy_buf, dummy_size);
   free(dummy_buf);


   return;
}  



/****************************************************************************
 *
 * Function: Parseflags(char *)
 *
 * Purpose: Figure out which TCP flags the current rule is interested in
 *
 * Arguments: rule => the rule string 
 *
 * Returns: void function
 *
 ***************************************************************************/

void ParseFlags(char *rule)
{
   char *fptr;
   char *fend;
   
   fptr = rule;

   while(!isalnum((char) *fptr))
	   fptr++;

   current->tcp_flags = 0;
   current->check_tcp_flags = 1;

   /* find the end of the alert string */
   fend = fptr + strlen(fptr); 

   while(fptr < fend)
   {
      switch((*fptr&0xFF))
      {
         case 'f':
         case 'F':
                 current->tcp_flags |= R_FIN;
                 break;

         case 's':
         case 'S':
                 current->tcp_flags |= R_SYN;
                 break;

         case 'r':
         case 'R':
                 current->tcp_flags |= R_RST;
                 break;

         case 'p':
         case 'P':
                 current->tcp_flags |= R_PSH;
                 break;

         case 'a':
         case 'A':
                 current->tcp_flags |= R_ACK;
                 break;

         case 'u':
         case 'U':
                 current->tcp_flags |= R_URG;
                 break;

         case '0':
		 current->tcp_flags = 0;
                 current->check_tcp_flags = 1;
		 break;

         default:
                 fprintf(stderr, "ERROR Line %d: bad TCP flag = \"%c\"\n", file_line, *fptr);
                 fprintf(stderr, "      Valid otions: UAPRSF or 0 for NO flags (e.g. NULL scan)\n");
                 exit(1);
      }

      fptr++;
   }

}




void ParseMessage(char *msg)
{
   char *ptr;
   char *end;
   int size;

   /* figure out where the message starts */
   ptr = index(msg,'"');

   if(ptr == NULL)
   {
      ptr = msg;
   }
   else
      ptr++;
   
   end = index(ptr,'"');

   if(end != NULL)
      *end = 0;

   while(isspace((char) *ptr)) ptr++;

   /* find the end of the alert string */
   size = strlen(msg);

   /* alloc space for the string and put it in the rule */
   if(size > 0)
   {
      current->message = (char *)malloc((sizeof(char)*size));
      strncpy(current->message, ptr, size);
      current->message[size-1] = 0;
   }
   else 
   {
      fprintf(stderr, "ERROR Line %d: bad alert message size %d\n", file_line, size);
   }
}



void ParseItype(char *number)
{
   char *type;

   type = number;

   while(isspace(*type))
      type++;

   if(isdigit(*type))
   {
      current->icmp_type = atoi(type);

      if((current->icmp_type > 18)||
	 (current->icmp_type < 0))
      {
         fprintf(stderr, "ERROR Line %d: Bad ICMP type: %s\n", file_line, type);
	 exit(1);
      }
	      
      current->use_icmp_type = 1;	      
      return;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d: Bad ICMP type: %s\n", file_line, type);
      exit(1);
   }  
}


void ParseIcode(char *type)
{
   while(isspace(*type))
      type++;

   if(isdigit(*type))
   {
      current->icmp_code = atoi(type);

      if((current->icmp_code > 15)||
	 (current->icmp_code < 0))
      {
         fprintf(stderr, "ERROR Line %d: Bad ICMP code: %s\n", file_line, type);
	 exit(1);
      }
      current->use_icmp_code = 1;	      
      return;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d: Bad ICMP code: %s\n", file_line, type);
      exit(1);
   }  
}

/****************************************************************
 *
 *  Function: mSearch(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int mSearch( char *buf, int blen, char *ptrn, int plen)
{
   char *eob = buf + blen; /* end of buffer */
   int pidx;
   int bidx;
   int tidx;

#ifdef  DEBUG
        int cmpcnt = 0;
#endif


   /* if pattern len > buffer len, no match */
   if( plen > blen ) 
   {
      return 0;
   }

   pidx = bidx = plen - 1;

   while( &buf[bidx] < eob ) 
   {
      if( ptrn[pidx] != buf[bidx] ) 
      {
#ifdef	DEBUG
         cmpcnt++;
#endif
         for(; pidx > -1 && ptrn[pidx] != buf[bidx]; pidx-- ) 
         {
#ifdef	DEBUG
            cmpcnt++;
#endif
         }

         if( pidx == -1 ) 
         {
            pidx = plen - 1;
            bidx += pidx + 1;
         } 
         else 
         {
            bidx += plen - pidx - 1;
            pidx = plen - 1;
         }
      } 
      else 
      {
         for(pidx = 0, tidx = bidx - plen + 1; pidx < plen && ptrn[pidx] == buf[tidx]; pidx++,tidx++ ) 
         {
#ifdef	DEBUG
           cmpcnt++;
#endif
         }

         if( pidx == plen ) 
         {
#ifdef	DEBUG
            fprintf(stdout, "match: compares = %d.\n", cmpcnt);
#endif	
            return 1;
         }

         pidx = plen - 1;
         bidx += 1;
      }
   }

#ifdef	DEBUG
   fprintf(stdout, "match: compares = %d.\n", cmpcnt);
#endif	
    return 0;
}



int CheckRules(Rule *list, NetData net, PrintIP pip)
{
   Rule *idx;  /* index ptr for walking the rules list */

   /* set the start ptr */
   idx = list;

   /* so I'm using goto's, so friggin what */
   /* you gotta problem with that jerky? (you lookin' at me?) */
   while(idx != NULL)
   {


      if(((unsigned int)idx->proto) != net.proto)
      {
		//printf("idx->proto:%d\n",idx->proto);
		//printf("net.proto:%d\n",net.proto);
		//printf("------hahahahaha-------\n");
         goto bottom;
      }
      if((idx->flags & ANY_SRC_IP) || 
         (idx->sip == (net.sip & idx->smask)))
      {

      }
      else
      {
		  //printf("------1-------\n");
         goto bottom;
		 
		 
      }

      if((idx->flags & ANY_SRC_PORT) ||
         ((idx->hsp>=net.sp)&&(idx->lsp<=net.sp)))
      {

      }
      else
      {
		 //printf("------2-------\n");
         goto bottom;
		 
      }

      if((idx->flags & ANY_DST_IP) ||
         (idx->dip == (net.dip & idx->dmask)))
      {

      }
      else
      {
		  //printf("------3-------\n");
         goto bottom;
      }

      if((idx->flags & ANY_DST_PORT) ||
         ((idx->hdp>=net.dp)&&(idx->ldp<=net.dp)))
      {

      }
      else
      {
		  //printf("------4-------\n");
         goto bottom;
      }

      if(net.proto == IPPROTO_TCP)
      {

         if(idx->check_tcp_flags)
         {
			if(idx->tcp_flags == net.tcp_flags) 
            {
            }
            else
            {
				//printf("------5-------\n");
               goto bottom;
            }
         }
      }


      if(idx->ttl)
      {

		 if(pip.ttl == idx->ttl)
		 {

		 }
		 else
		 {
			//printf("------6-------\n");
			goto bottom;
		 }
      }

	  
	  
	  
      // if(idx->use_icmp_type)
      // {

	 // if(idx->icmp_type != pip.icmp_type)
	 // {

            // goto bottom;
	 // }
      // }

      // if(idx->use_icmp_code)
      // {
	 // if(idx->icmp_code != pip.icmp_code)
	 // {
            // goto bottom;
	 // }
      // }

	  
	  
      if(idx->pattern_size > 0)
      {

         if(mSearch(pip.data,pip.dsize,idx->pattern_buf,idx->pattern_size))
         {

         }
         else
         {
			//printf("------6-------\n");
            goto bottom;
         }
      }

      current = idx;

      switch(idx->type)
      {
         case RULE_PASS: 
                       //printf("RULE_PASS\n");
					   return 1;
                      
         case RULE_ALERT: //printf("RULE_ALERT\n");
						  //AlertPkt();
                          return 1;

         case RULE_LOG: //printf("RULE_LOG\n");
						//LogPkt();
                        return 1;
      }
bottom:
      idx = idx->next;
		//printf("bottem\n");
   } 

   return 0;
}
NetData snort_pktcon(struct rte_mbuf* pkt, NetData net)
{
		unsigned char * d = PktData(pkt);
		d = d + 14;
		net.sip = 0; 
		int i;
		for(i = 0;i < 3;i ++)
		{
			net.sip = net.sip + *(d +12 + i);
			net.sip = net.sip << 8;
		}
		net.sip = net.sip + *(d +12 + 3);
		net.dip = 0; 
		for(i = 0;i < 3;i ++)
		{
			net.dip = net.dip + *(d +16 + i);
			net.dip = net.dip << 8;
		}
		net.dip = net.dip + *(d +16 + 3);
		net.sp = 0;
		net.sp = net.sp + *(d +20);
		net.sp = (net.sp << 8);
		net.sp = net.sp + *(d +20 + 1);
		net.dp = 0;
		net.dp = net.dp + *(d + 20);
		net.dp = net.dp << 8;
		net.dp = net.dp + *(d + 20 + 1);
		net.proto = (unsigned int)*(d + 9);
		net.tcp_flags = *(d + 33);
		
		pip.ttl = (unsigned char)*(d + 8);
		if(net.proto == 6)
		{
			unsigned char ip_header_len = ((*d << 4) >> 4) * 4;
			unsigned short ip_len = ((*(d + 2)) << 8) + (*(d + 3));
			unsigned int tcp_header_len = ((*(d + ip_header_len + 12)) >> 4) * 4;
			pip.data = (char *)(d + ip_header_len + tcp_header_len);
			pip.dsize = (unsigned int)ip_len - ip_header_len - tcp_header_len;		
			// printf("ip_header_len:%d\n",ip_header_len);
			// printf("ip_len:%d\n",ip_len);
			// printf("tcp_header_len:%d\n",tcp_header_len);
			// printf("pip.dsize:%d\n",pip.dsize);
			// printf("pip.data:%c\n",*pip.data);
		}
		// printf("sip:%ld\n",net.sip);
		// printf("dip:%ld\n",net.dip);
		// printf("sp:%d\n",net.sp);
		// printf("dp:%d\n",net.dp);
		// printf("net.proto:%d\n",net.proto);
		// printf("net.tcp_flags:%d\n",net.tcp_flags);
		// printf("pip.ttl:%d\n",pip.ttl);
		return net;
		
		
}



void snort_state_action(struct rte_mbuf* pkt)
{
		//uint64_t cycle_start = rte_get_timer_cycles();

		NetData net;
		net = snort_pktcon(pkt, net);
		// printf("snort_sa run\n\n");
		if(!CheckRules(AlertList, net, pip))
		{
			// printf("AlertList run\n\n");
         if(!CheckRules(PassList, net, pip))
         {
			// printf("PassList run\n\n");
            CheckRules(LogList, net, pip);
			// printf("LogList run\n\n");
         }
		}
		//uint64_t cycle_end = rte_get_timer_cycles();
		//printf("cycle: %lu \n", (cycle_end - cycle_start));
}