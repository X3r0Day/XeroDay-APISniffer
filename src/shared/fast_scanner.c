#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

// builds with: gcc -shared -fPIC -O3 fast_scanner.c -o fast_scanner.so
// -lpcre2-8

typedef void (*MatchCallback)(const char *api_name, const char *match_text);

typedef struct {
  pcre2_code *re;
  char *name;
} CompiledPattern;

CompiledPattern *patterns = NULL;
int num_patterns = 0;

void init_scanner(int count, const char **names, const char **regexes) {
  if (patterns != NULL) {
    return; // already loaded
  }
  if (count <= 0)
    return;

  patterns = malloc(sizeof(CompiledPattern) * count);
  if (!patterns)
    return;
  num_patterns = count;

  for (int i = 0; i < count; i++) {
    int errornumber;
    PCRE2_SIZE erroroffset;

    patterns[i].name = strdup(names[i]);
    if (!patterns[i].name) {
      patterns[i].re = NULL;
      continue;
    }

    patterns[i].re =
        pcre2_compile((PCRE2_SPTR)regexes[i], PCRE2_ZERO_TERMINATED, 0,
                      &errornumber, &erroroffset, NULL);

    // bad regex, just skip it and keep going
  }
}

void free_scanner() {
  if (!patterns)
    return;
  for (int i = 0; i < num_patterns; i++) {
    if (patterns[i].name)
      free(patterns[i].name);
    if (patterns[i].re)
      pcre2_code_free(patterns[i].re);
  }
  free(patterns);
  patterns = NULL;
  num_patterns = 0;
}

double shannon_entropy_c(const char *data) {
  if (!data)
    return 0.0;
  size_t len = strlen(data);
  if (len == 0)
    return 0.0;

  int counts[256] = {0};
  for (size_t i = 0; i < len; i++) {
    counts[(unsigned char)data[i]]++;
  }

  double entropy = 0.0;
  for (int i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      double p = (double)counts[i] / len;
      entropy -= p * log2(p);
    }
  }
  return entropy;
}

void scan_text_c(const char *text, MatchCallback cb) {
  if (!patterns || !text || !cb)
    return;

  size_t subject_length = strlen(text);
  pcre2_match_data *match_data =
      pcre2_match_data_create(1, NULL); // only need the full match
  if (!match_data)
    return;

  for (int i = 0; i < num_patterns; i++) {
    if (!patterns[i].re)
      continue;

    PCRE2_SIZE start_offset = 0;
    while (start_offset < subject_length) {
      int rc = pcre2_match(patterns[i].re, (PCRE2_SPTR)text, subject_length,
                           start_offset, 0, match_data, NULL);

      if (rc < 0) {
        // done with this pattern
        break;
      }

      PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
      int match_len = ovector[1] - ovector[0];

      if (match_len > 0) {
        char *match_str = malloc(match_len + 1);
        if (match_str) {
          memcpy(match_str, text + ovector[0], match_len);
          match_str[match_len] = '\0';
          cb(patterns[i].name, match_str);
          free(match_str);
        }
        start_offset = ovector[1];
      } else {
        // zero-width match, bump forward so we dont loop forever
        start_offset = ovector[0] + 1;
      }
    }
  }
  pcre2_match_data_free(match_data);
}
