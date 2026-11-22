// msc_run RULES REQFILE -> prints the HTTP status ModSecurity decides (200 = passed).
// REQFILE: length-prefixed fields "<n>\n<n bytes>" in order: method, uri, body,
// then any number of header fields "Name: value" (so any byte, even NUL, survives).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>
static char *field(FILE *f, size_t *len) {
  size_t n; if (fscanf(f, "%zu", &n) != 1 || fgetc(f) != '\n') return NULL;
  char *b = calloc(n + 1, 1); if (fread(b, 1, n, f) != n) { free(b); return NULL; } *len = n; return b;
}
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  ModSecurity *m = msc_init(); const char *err = NULL;
  RulesSet *rs = msc_create_rules_set();
  if (msc_rules_add(rs, "SecRuleEngine On\nSecRequestBodyAccess On\n", &err) < 0 || msc_rules_add_file(rs, argv[1], &err) < 0) { printf("ERR %s\n", err); return 3; }
  FILE *f = fopen(argv[2], "rb"); if (!f) return 4;
  size_t ml, ul, bl, hl; char *method = field(f, &ml), *uri = field(f, &ul), *body = field(f, &bl);
  if (!method || !uri || !body) return 5;
  Transaction *t = msc_new_transaction(m, rs, NULL);
  msc_process_connection(t, "127.0.0.1", 40000, "127.0.0.1", 80);
  msc_process_uri(t, uri, method, "1.1");
  char *h;
  while ((h = field(f, &hl))) { char *c = strchr(h, ':'); if (!c) continue; *c = 0; char *v = c + 1; while (*v == ' ') v++;
    msc_add_request_header(t, (unsigned char*)h, (unsigned char*)v); }
  msc_process_request_headers(t);
  if (bl) msc_append_request_body(t, (unsigned char*)body, bl);
  msc_process_request_body(t);
  ModSecurityIntervention it; memset(&it, 0, sizeof it); it.status = 200;
  msc_intervention(t, &it);
  printf("%d\n", it.status);
  return 0;
}
